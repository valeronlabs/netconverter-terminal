"""Frozen regression: masked mapping reads exist despite the old blanket refusal."""
from tests.test_guided_prescan_037 import bridge_for


def test_masked_disclosure_matches_advertised_mapping_reads(tmp_path):
    tools = ('get_account', 'get_mapping_questions', 'validate_mapping', 'propose_operations', 'submit_conversion')
    bridge, _, _ = bridge_for(tmp_path, level='masked', tools=tools)
    names = {t['name'] for t in bridge.list_tools()}
    result = bridge.call('account', {})['structuredContent']['guided_migration']
    assert result['tools'] == ['get_mapping_questions', 'validate_mapping']
    assert set(result['tools']) <= names
    assert 'lists no guided' not in result.get('fix', '')
    assert 'propose_operations' not in names and 'submit_conversion' not in names


def test_masked_disclosure_does_not_invent_mapping_support(tmp_path):
    bridge, _, _ = bridge_for(tmp_path, level='masked', tools=('get_account',))
    result = bridge.call('account', {})['structuredContent']['guided_migration']
    assert result['tools'] == []
