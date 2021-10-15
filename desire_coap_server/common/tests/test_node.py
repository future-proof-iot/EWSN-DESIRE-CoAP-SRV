"""Node test module."""

import dataclasses
import pytest
import random

from common.node import Node, Nodes
from common import TEST_NODE_UID_0
from desire_coap.payloads import EncounterData, ErtlPayload, PetElement


@pytest.fixture(autouse=True)
def testnode():
    """A test node object for testing"""
    node = Node(TEST_NODE_UID_0)
    return node


def test_node_add_rmv_ertl(testnode):
    """Tests adding and removing rtl data to a Node"""
    assert not testnode.ertl
    with open("static/ertl.json") as json_file:
        ertl = ErtlPayload.from_json_str("".join(json_file.readlines()))
    testnode.add_ertl(ertl)
    assert testnode.ertl
    testnode.rmv_ertl(ertl)
    assert not testnode.ertl


def test_node_get_etl(testnode):
    """Tests return the encounter token list from the ERTL data"""
    ertl_data_1 = ErtlPayload.rand(5)
    ertl_data_2 = ErtlPayload.rand(5)
    expected_etl_1 = [pet.pet.etl for pet in ertl_data_1.pets]
    expected_etl_2 = [pet.pet.etl for pet in ertl_data_2.pets]
    testnode.add_ertl(ertl_data_1)
    testnode.add_ertl(ertl_data_2)
    assert len(testnode.ertl) == 2
    etl = testnode.get_etl()
    assert all(elem in etl for elem in expected_etl_1)
    assert all(elem in etl for elem in expected_etl_2)


def test_node_get_rtl(testnode):
    """Tests return the request token list from the ERTL data"""
    ertl_data_1 = ErtlPayload.rand(5)
    ertl_data_2 = ErtlPayload.rand(5)
    expected_rtl_1 = [pet.pet.rtl for pet in ertl_data_1.pets]
    expected_rtl_2 = [pet.pet.rtl for pet in ertl_data_2.pets]
    testnode.add_ertl(ertl_data_1)
    testnode.add_ertl(ertl_data_2)
    assert len(testnode.ertl) == 2
    etl = testnode.get_rtl()
    assert all(elem in etl for elem in expected_rtl_1)
    assert all(elem in etl for elem in expected_rtl_2)


def test_node_is_contact(testnode):
    """Test that contacts for an rtl are correctly returned"""
    rtl = list()
    for _ in range(1, 5):
        ertl = ErtlPayload.rand(1)
        testnode.add_ertl(ertl)
        # we use the etl since the matching exposed node should have
        # inverted etl/rtl
        rtl.append(ertl.pets[0].pet.etl)
    not_seen_ertl = ErtlPayload.rand(1)
    assert not testnode.is_contact([not_seen_ertl.pets[0].pet.etl])
    assert testnode.is_contact([rtl[0]])
    assert testnode.is_contact([rtl[1]])


def test_node_update_contact(testnode):
    """Test updating a node's infection status"""
    ertl = ErtlPayload.rand(1)
    testnode.add_ertl(ertl)
    assert not testnode.exposed
    testnode.update_contact([ertl.pets[0].pet.etl])
    assert testnode.exposed


def test_nodes_update_contact():
    """Test updating contact status of multiple nodes"""
    node_list = []
    rtl = []
    for i in range(0, 2):
        node = Node(f"DW000{i}")
        ertl = ErtlPayload.rand(1)
        node.add_ertl(ertl)
        # we use the etl since the matching exposed node should have
        # inverted etl/rtl
        rtl.append(ertl.pets[0].pet.etl)
        node_list.append(node)
    nodes = Nodes(node_list)
    for node in nodes.nodes:
        assert not node.exposed
    nodes.update_contact([rtl[0]])
    assert nodes.nodes[0].exposed
    assert not nodes.nodes[1].exposed
    nodes.update_contact(rtl)
    for node in nodes.nodes:
        assert node.exposed


def test_resolve_contacts():
    """Test resolve contacts from encounter pets"""

    def _mirror_pet(pet: PetElement):
        ed = pet.pet
        _ed = dataclasses.replace(ed)  #  clone
        _ed.rtl = ed.etl
        _ed.etl = ed.rtl
        return PetElement(_ed)

    # populate three nodes:
    _nodes = [Node(f"DWM000{i}") for i in range(3)]
    # generate three random pets
    ertl = ErtlPayload.rand(3)
    # encouter matrix
    # node 0 has ecountered nodes 1 and 2
    # node 1 has encountered nodes 0 and 2
    # node 2 has encoutered nodes 0 and 1
    _nodes[0].add_ertl(ErtlPayload(ertl.epoch, [ertl.pets[0], ertl.pets[1]]))
    _nodes[1].add_ertl(
        ErtlPayload(ertl.epoch, [_mirror_pet(ertl.pets[0]), ertl.pets[2]])
    )
    _nodes[2].add_ertl(
        ErtlPayload(ertl.epoch, [_mirror_pet(ertl.pets[1]), _mirror_pet(ertl.pets[2])])
    )
    nodes = Nodes(_nodes)

    assert nodes.resolve_contacts(_nodes[0].get_rtl()) == [_nodes[1].uid, _nodes[2].uid]
    assert nodes.resolve_contacts(_nodes[1].get_rtl()) == [_nodes[0].uid, _nodes[2].uid]
    assert nodes.resolve_contacts(_nodes[2].get_rtl()) == [_nodes[0].uid, _nodes[1].uid]
