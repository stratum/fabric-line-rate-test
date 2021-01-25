# SPDX-FileCopyrightText: Copyright 2020-present Open Networking Foundation.
# SPDX-License-Identifier: Apache-2.0

# A module that includes all P4Runtime related utilities.

from collections import Counter
from functools import partialmethod
import grpc
import queue
import threading
import time
import socket

from p4.v1 import p4runtime_pb2, p4runtime_pb2_grpc
from p4.config.v1 import p4info_pb2
from google.rpc import code_pb2, status_pb2

# Convert integer (with length) to binary byte string
def stringify(n, length):
    return n.to_bytes(length, byteorder="big")


def ipv4_to_binary(addr):
    return socket.inet_aton(addr)


def mac_to_binary(addr):
    return bytes.fromhex(addr.replace(":", ""))


# Used to indicate that the gRPC error Status object returned by the server has
# an incorrect format.
class P4RuntimeErrorFormatException(Exception):
    def __init__(self, message):
        super(P4RuntimeErrorFormatException, self).__init__(message)


# Used to iterate over the p4.Error messages in a gRPC error Status object
class P4RuntimeErrorIterator:
    def __init__(self, grpc_error):
        assert grpc_error.code() == grpc.StatusCode.UNKNOWN
        self.grpc_error = grpc_error

        error = None
        # The gRPC Python package does not have a convenient way to access the
        # binary details for the error: they are treated as trailing metadata.
        for meta in self.grpc_error.trailing_metadata():
            if meta[0] == "grpc-status-details-bin":
                error = status_pb2.Status()
                error.ParseFromString(meta[1])
                break
        if error is None:
            raise P4RuntimeErrorFormatException("No binary details field")

        # if len(error.details) == 0:
        #     raise P4RuntimeErrorFormatException(
        #         "Binary details field has empty Any details repeated field")
        self.errors = error.details
        self.idx = 0

    def __iter__(self):
        return self

    def __next__(self):
        while self.idx < len(self.errors):
            p4_error = p4runtime_pb2.Error()
            one_error_any = self.errors[self.idx]
            if not one_error_any.Unpack(p4_error):
                raise P4RuntimeErrorFormatException(
                    "Cannot convert Any message to p4.Error"
                )
            if p4_error.canonical_code == code_pb2.OK:
                continue
            v = self.idx, p4_error
            self.idx += 1
            return v
        raise StopIteration


# P4Runtime uses a 3-level message in case of an error during the processing of
# a write batch. This means that if we do not wrap the grpc.RpcError inside a
# custom exception, we can end-up with a non-helpful exception message in case
# of failure as only the first level will be printed. In this custom exception
# class, we extract the nested error message (one for each operation included
# in the batch) in order to print error code + user-facing message.
# See P4 Runtime documentation for more details on error-reporting.
class P4RuntimeException(Exception):
    def __init__(self, grpc_error):
        assert grpc_error.code() == grpc.StatusCode.UNKNOWN
        super(P4RuntimeException, self).__init__()
        self.grpc_error = grpc_error
        self.errors = []
        try:
            error_iterator = P4RuntimeErrorIterator(grpc_error)
            for error_tuple in error_iterator:
                self.errors.append(error_tuple)
        except P4RuntimeErrorFormatException:
            raise  # just propagate exception for now

    def __str__(self):
        message = "Error(s) during RPC: {} {}\n".format(
            self.grpc_error.code(), self.grpc_error.details()
        )
        for idx, p4_error in self.errors:
            code_name = code_pb2._CODE.values_by_number[p4_error.canonical_code].name
            message += "\t* At index {}: {}, '{}'\n".format(
                idx, code_name, p4_error.message
            )
        return message


class P4RuntimeClient(object):
    """
    P4Runtime Client
    """

    def __init__(
        self, grpc_addr="localhost:9339", device_id=1, p4info_path=None, election_id=1
    ):
        # TODO, check p4info is valid or not
        self.channel = grpc.insecure_channel(grpc_addr)
        self.stub = p4runtime_pb2_grpc.P4RuntimeStub(self.channel)
        self.election_id = election_id

    def start(self):
        # Set up stream
        self.stream_out_q = queue.Queue()
        self.stream_in_q = queue.Queue()

        def stream_req_iterator():
            while True:
                p = self.stream_out_q.get()
                if p is None:
                    break
                yield p

        def stream_recv(stream):
            for p in stream:
                self.stream_in_q.put(p)

        self.stream = self.stub.StreamChannel(stream_req_iterator())
        self.stream_recv_thread = threading.Thread(
            target=stream_recv, args=(self.stream,)
        )
        self.stream_recv_thread.start()

        # Handshake with device
        req = p4runtime_pb2.StreamMessageRequest()
        arbitration = req.arbitration
        arbitration.device_id = self.device_id
        election_id = arbitration.election_id
        election_id.high = 0
        election_id.low = self.election_id
        self.stream_out_q.put(req)

        rep = self.get_stream_packet("arbitration", timeout=2)
        if rep is None:
            self.fail("Failed to establish handshake")

    def stop(self):
        self.stream_out_q.put(None)
        self.stream_recv_thread.join()

    def import_p4info_names(self, p4info):
        """
        Import all name and ID from given p4info
        """
        self.p4info_obj_map = {}
        self.p4info_id_to_name = {}
        suffix_count = Counter()
        for p4_obj_type in [
            "tables",
            "action_profiles",
            "actions",
            "counters",
            "direct_counters",
        ]:
            for obj in getattr(p4info, p4_obj_type):
                pre = obj.preamble
                suffix = None
                for s in reversed(pre.name.split(".")):
                    suffix = s if suffix is None else s + "." + suffix
                    key = (p4_obj_type, suffix)
                    self.p4info_obj_map[key] = obj
                    suffix_count[key] += 1
                self.p4info_id_to_name[pre.id] = pre.name
        for key, c in suffix_count.items():
            if c > 1:
                del self.p4info_obj_map[key]

        # Add p4info object and object id "getters" for each object type; these are
        # just wrappers around self.get_obj and self.get_obj_id.
        # For example: self.get_table(x) and self.get_table_id(x) respectively call
        # get_obj("tables", x) and get_obj_id("tables", x)
        for obj_type, nickname in [
            ("tables", "table"),
            ("action_profiles", "ap"),
            ("actions", "action"),
            ("counters", "counter"),
            ("direct_counters", "direct_counter"),
        ]:
            name = "_".join(["get", nickname])
            setattr(self, name, partialmethod(self.get_obj, obj_type))
            name = "_".join(["get", nickname, "id"])
            setattr(self, name, partialmethod(self.get_obj_id, obj_type))

    def get_obj(self, p4_obj_type, p4_name):
        key = (p4_obj_type, p4_name)
        obj = self.p4info_obj_map.get(key, None)
        if obj is None:
            raise Exception(
                "Unable to find {} '{}' in p4info".format(p4_obj_type, p4_name)
            )
        return obj

    def get_obj_id(self, p4_obj_type, p4_name):
        obj = self.get_obj(p4_obj_type, p4_name)
        return obj.preamble.id

    def get_stream_packet(self, type_, timeout=1):
        start = time.time()
        try:
            while True:
                remaining = timeout - (time.time() - start)
                if remaining < 0:
                    break
                msg = self.stream_in_q.get(timeout=remaining)
                if not msg.HasField(type_):
                    continue
                return msg
        except Exception:  # timeout expired
            pass
        return None

    # These are attempts at convenience functions aimed at making writing
    # P4Runtime PTF tests easier.

    class MF(object):
        def __init__(self, mf_name):
            self.name = mf_name

    class Exact(MF):
        def __init__(self, mf_name, v):
            super(P4RuntimeClient.Exact, self).__init__(mf_name)
            self.v = v

        def add_to(self, mf_id, mk):
            mf = mk.add()
            mf.field_id = mf_id
            mf.exact.value = self.v

    class Lpm(MF):
        def __init__(self, mf_name, v, pLen):
            super(P4RuntimeClient.Lpm, self).__init__(mf_name)
            self.v = v
            self.pLen = pLen

        def add_to(self, mf_id, mk):
            # P4Runtime mandates that the match field should be omitted for
            # "don't care" LPM matches (i.e. when prefix length is zero)
            if self.pLen == 0:
                return
            mf = mk.add()
            mf.field_id = mf_id
            mf.lpm.prefix_len = self.pLen
            mf.lpm.value = b""

            # P4Runtime now has strict rules regarding ternary matches: in the
            # case of LPM, trailing bits in the value (after prefix) must be set
            # to 0.
            first_byte_masked = self.pLen // 8
            for i in range(first_byte_masked):
                mf.lpm.value += stringify(self.v[i], 1)
            if first_byte_masked == len(self.v):
                return
            r = self.pLen % 8
            mf.lpm.value += stringify(self.v[first_byte_masked] & (0xFF << (8 - r)), 1)
            for i in range(first_byte_masked + 1, len(self.v)):
                mf.lpm.value += b"\x00"

    class Ternary(MF):
        def __init__(self, mf_name, v, mask):
            super(P4RuntimeClient.Ternary, self).__init__(mf_name)
            self.v = v
            self.mask = mask

        def add_to(self, mf_id, mk):
            # P4Runtime mandates that the match field should be omitted for
            # "don't care" ternary matches (i.e. when mask is zero)
            if all(c == b"\x00" for c in self.mask):
                return
            mf = mk.add()
            mf.field_id = mf_id
            assert len(self.mask) == len(self.v)
            mf.ternary.mask = self.mask
            mf.ternary.value = b""
            # P4Runtime now has strict rules regarding ternary matches: in the
            # case of Ternary, "don't-care" bits in the value must be set to 0
            for i in range(len(self.mask)):
                mf.ternary.value += stringify(self.v[i] & self.mask[i], 1)

    class Range(MF):
        def __init__(self, mf_name, low, high):
            super(P4RuntimeClient.Range, self).__init__(mf_name)
            self.low = low
            self.high = high

        def add_to(self, mf_id, mk):
            # P4Runtime mandates that the match field should be omitted for
            # "don't care" range matches (i.e. when all possible values are
            # included in the range)
            # TODO(antonin): negative values?
            low_is_zero = all(c == b"\x00" for c in self.low)
            high_is_max = all(c == b"\xff" for c in self.high)
            if low_is_zero and high_is_max:
                return
            mf = mk.add()
            mf.field_id = mf_id
            assert len(self.high) == len(self.low)
            mf.range.low = self.low
            mf.range.high = self.high

    # Sets the match key for a p4::TableEntry object. mk needs to be an
    # iterable object of MF instances
    def set_match_key(self, table_entry, t_name, mk):
        for mf in mk:
            mf_id = self.get_mf_id(t_name, mf.name)
            mf.add_to(mf_id, table_entry.match)

    def set_action(self, action, a_name, params):
        action.action_id = self.get_action_id(a_name)
        for p_name, v in params:
            param = action.params.add()
            param.param_id = self.get_param_id(a_name, p_name)
            param.value = v

    # Sets the action & action data for a p4::TableEntry object. params needs
    # to be an iterable object of 2-tuples (<param_name>, <value>).
    def set_action_entry(self, table_entry, a_name, params):
        self.set_action(table_entry.action.action, a_name, params)

    def _write(self, req):
        try:
            return self.stub.Write(req)
        except grpc.RpcError as e:
            if e.code() != grpc.StatusCode.UNKNOWN:
                raise e
            raise P4RuntimeException(e)

    def read_request(self, req):
        entities = []
        try:
            for resp in self.stub.Read(req):
                entities.extend(resp.entities)
        except grpc.RpcError as e:
            if e.code() != grpc.StatusCode.UNKNOWN:
                raise e
            raise P4RuntimeException(e)
        return entities

    def write_request(self, req, store=True):
        rep = self._write(req)
        if store:
            self.reqs.append(req)
        return rep

    def get_new_write_request(self):
        req = p4runtime_pb2.WriteRequest()
        req.device_id = self.device_id
        election_id = req.election_id
        election_id.high = 0
        election_id.low = self.election_id
        return req

    def get_new_read_request(self):
        req = p4runtime_pb2.ReadRequest()
        req.device_id = self.device_id
        return req

    def get_new_read_response(self):
        resp = p4runtime_pb2.ReadResponse()
        return resp

    #
    # Convenience functions to build and send P4Runtime write requests
    #

    def _push_update_member(self, req, ap_name, mbr_id, a_name, params, update_type):
        update = req.updates.add()
        update.type = update_type
        ap_member = update.entity.action_profile_member
        ap_member.action_profile_id = self.get_ap_id(ap_name)
        ap_member.member_id = mbr_id
        self.set_action(ap_member.action, a_name, params)

    def push_update_add_member(self, req, ap_name, mbr_id, a_name, params):
        self._push_update_member(
            req, ap_name, mbr_id, a_name, params, p4runtime_pb2.Update.INSERT
        )

    def push_update_modify_member(self, req, ap_name, mbr_id, a_name, params):
        self._push_update_member(
            req, ap_name, mbr_id, a_name, params, p4runtime_pb2.Update.MODIFY
        )

    def push_update_modify_group(self, req, ap_name, grp_id, grp_size, mbr_ids):
        update = req.updates.add()
        update.type = p4runtime_pb2.Update.MODIFY
        ap_group = update.entity.action_profile_group
        ap_group.action_profile_id = self.get_ap_id(ap_name)
        ap_group.group_id = grp_id
        for mbr_id in mbr_ids:
            member = ap_group.members.add()
            member.member_id = mbr_id
            member.weight = 1
        ap_group.max_size = grp_size

    def push_update_add_group(self, req, ap_name, grp_id, grp_size=32, mbr_ids=()):
        update = req.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        ap_group = update.entity.action_profile_group
        ap_group.action_profile_id = self.get_ap_id(ap_name)
        ap_group.group_id = grp_id
        ap_group.max_size = grp_size
        for mbr_id in mbr_ids:
            member = ap_group.members.add()
            member.member_id = mbr_id
            member.weight = 1

    def push_update_set_group_membership(self, req, ap_name, grp_id, mbr_ids=()):
        update = req.updates.add()
        update.type = p4runtime_pb2.Update.MODIFY
        ap_group = update.entity.action_profile_group
        ap_group.action_profile_id = self.get_ap_id(ap_name)
        ap_group.group_id = grp_id
        for mbr_id in mbr_ids:
            member = ap_group.members.add()
            member.member_id = mbr_id

    def push_update_add_entry_to_action(
        self, req, t_name, mk, a_name, params, priority=0
    ):
        update = req.updates.add()
        table_entry = update.entity.table_entry
        table_entry.table_id = self.get_table_id(t_name)
        table_entry.priority = priority
        if mk is None or len(mk) == 0:
            table_entry.is_default_action = True
            update.type = p4runtime_pb2.Update.MODIFY
        else:
            update.type = p4runtime_pb2.Update.INSERT
            self.set_match_key(table_entry, t_name, mk)
        self.set_action_entry(table_entry, a_name, params)

    def push_update_add_entry_to_member(self, req, t_name, mk, mbr_id):
        update = req.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        table_entry = update.entity.table_entry
        table_entry.table_id = self.get_table_id(t_name)
        self.set_match_key(table_entry, t_name, mk)
        table_entry.action.action_profile_member_id = mbr_id

    def push_update_add_entry_to_group(self, req, t_name, mk, grp_id):
        update = req.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        table_entry = update.entity.table_entry
        table_entry.table_id = self.get_table_id(t_name)
        self.set_match_key(table_entry, t_name, mk)
        table_entry.action.action_profile_group_id = grp_id

    def send_request_add_member(self, ap_name, mbr_id, a_name, params):
        req = self.get_new_write_request()
        self.push_update_add_member(req, ap_name, mbr_id, a_name, params)
        return req, self.write_request(req)

    def send_request_modify_member(self, ap_name, mbr_id, a_name, params):
        req = self.get_new_write_request()
        self.push_update_modify_member(req, ap_name, mbr_id, a_name, params)
        return req, self.write_request(req, store=False)

    def send_request_modify_group(self, ap_name, grp_id, grp_size=32, mbr_ids=()):
        req = self.get_new_write_request()
        self.push_update_modify_group(req, ap_name, grp_id, grp_size, mbr_ids)
        return req, self.write_request(req, store=False)

    def send_request_add_group(self, ap_name, grp_id, grp_size=32, mbr_ids=()):
        req = self.get_new_write_request()
        self.push_update_add_group(req, ap_name, grp_id, grp_size, mbr_ids)
        return req, self.write_request(req)

    def send_request_set_group_membership(self, ap_name, grp_id, mbr_ids=()):
        req = self.get_new_write_request()
        self.push_update_set_group_membership(req, ap_name, grp_id, mbr_ids)
        return req, self.write_request(req, store=False)

    def send_request_add_entry_to_action(self, t_name, mk, a_name, params, priority=0):
        req = self.get_new_write_request()
        self.push_update_add_entry_to_action(req, t_name, mk, a_name, params, priority)
        return req, self.write_request(req)

    def send_request_add_entry_to_member(self, t_name, mk, mbr_id):
        req = self.get_new_write_request()
        self.push_update_add_entry_to_member(req, t_name, mk, mbr_id)
        return req, self.write_request(req)

    def send_request_add_entry_to_group(self, t_name, mk, grp_id):
        req = self.get_new_write_request()
        self.push_update_add_entry_to_group(req, t_name, mk, grp_id)
        return req, self.write_request(req)

    def read_direct_counter(self, table_entry):
        req = self.get_new_read_request()
        entity = req.entities.add()
        direct_counter_entry = entity.direct_counter_entry
        direct_counter_entry.table_entry.CopyFrom(table_entry)

        for entity in self.read_request(req):
            if entity.HasField("direct_counter_entry"):
                return entity.direct_counter_entry
        return None

    def write_direct_counter(self, table_entry, byte_count, packet_count):
        req = self.get_new_write_request()
        update = req.updates.add()
        update.type = p4runtime_pb2.Update.MODIFY
        direct_counter_entry = update.entity.direct_counter_entry
        direct_counter_entry.table_entry.CopyFrom(table_entry)
        direct_counter_entry.data.byte_count = byte_count
        direct_counter_entry.data.packet_count = packet_count
        return req, self.write_request(req, store=False)

    def read_indirect_counter(self, c_name, c_index, typ):
        # Check counter type with P4Info
        counter = self.get_counter(c_name)
        counter_type_unit = p4info_pb2.CounterSpec.Unit.items()[counter.spec.unit][0]
        if counter_type_unit != "BOTH" and counter_type_unit != typ:
            raise Exception(
                "Counter "
                + c_name
                + " is of type "
                + counter_type_unit
                + ", but requested: "
                + typ
            )
        req = self.get_new_read_request()
        entity = req.entities.add()
        counter_entry = entity.counter_entry
        c_id = self.get_counter_id(c_name)
        counter_entry.counter_id = c_id
        index = counter_entry.index
        index.index = c_index

        for entity in self.read_request(req):
            if entity.HasField("counter_entry"):
                return entity.counter_entry
        return None

    def write_indirect_counter(
        self, c_name, c_index, byte_count=None, packet_count=None
    ):
        # Get counter type with P4Info
        counter = self.get_counter(c_name)
        counter_type_unit = p4info_pb2.CounterSpec.Unit.items()[counter.spec.unit][0]

        req = self.get_new_write_request()
        update = req.updates.add()
        update.type = p4runtime_pb2.Update.MODIFY
        counter_entry = update.entity.counter_entry

        c_id = self.get_counter_id(c_name)
        counter_entry.counter_id = c_id
        index = counter_entry.index
        index.index = c_index

        counter_data = counter_entry.data

        if counter_type_unit == "BOTH" or counter_type_unit == "BYTES":
            if byte_count is None:
                raise Exception(
                    "Counter "
                    + c_name
                    + " is of type "
                    + counter_type_unit
                    + ", byte_count cannot be None"
                )
            counter_data.byte_count = byte_count
        if counter_type_unit == "BOTH" or counter_type_unit == "PACKETS":
            if packet_count is None:
                raise Exception(
                    "Counter "
                    + c_name
                    + " is of type "
                    + counter_type_unit
                    + ", packet_count cannot be None"
                )
            counter_data.packet_count = packet_count
        return req, self.write_request(req, store=False)

    def read_table_entry(self, t_name, mk, priority=0):
        req = self.get_new_read_request()
        entity = req.entities.add()
        table_entry = entity.table_entry
        table_entry.table_id = self.get_table_id(t_name)
        table_entry.priority = priority
        if mk is None or len(mk) == 0:
            table_entry.is_default_action = True
        else:
            self.set_match_key(table_entry, t_name, mk)

        for entity in self.read_request(req):
            if entity.HasField("table_entry"):
                return entity.table_entry
        return None

    def read_action_profile_member(self, ap_name, mbr_id):
        req = self.get_new_read_request()
        entity = req.entities.add()
        action_profile_member = entity.action_profile_member
        action_profile_member.action_profile_id = self.get_ap_id(ap_name)
        action_profile_member.member_id = mbr_id

        for entity in self.read_request(req):
            if entity.HasField("action_profile_member"):
                return entity.action_profile_member
        return None

    def read_action_profile_group(self, ap_name, grp_id):
        req = self.get_new_read_request()
        entity = req.entities.add()
        action_profile_member = entity.action_profile_group
        action_profile_member.action_profile_id = self.get_ap_id(ap_name)
        action_profile_member.group_id = grp_id

        for entity in self.read_request(req):
            if entity.HasField("action_profile_group"):
                return entity.action_profile_group
        return None

    def is_default_action_update(self, update):
        return (
            update.type == p4runtime_pb2.Update.MODIFY
            and update.entity.WhichOneof("entity") == "table_entry"
            and update.entity.table_entry.is_default_action
        )
