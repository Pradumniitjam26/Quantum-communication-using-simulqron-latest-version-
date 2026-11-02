from fastapi import APIRouter
from protocol_manager import execute_protocol
from database.key_manager import latest_key, get_key, list_active_keys, key_stats, keys_by_status

router = APIRouter()


@router.get('/latest_key')
def api_latest_key():
    return {
        'key': latest_key()
    }


@router.get('/active_keys')
def api_active_keys():
    return {
        'keys': list_active_keys()
    }


@router.get('/key/{key_id}')
def api_key(key_id: int):
    return {
        'key': get_key(key_id)
    }


@router.post('/generate_bb84')
def generate_bb84():
    success = execute_protocol('BB84')
    if not success:
        return {'status': 'FAILED'}
    return {
        'status': 'SUCCESS',
        'protocol': 'BB84',
        'key': latest_key()
    }


@router.get('/key_stats')
def api_key_stats():
    return {
        'stats': key_stats()
    }


@router.get('/keys_by_status/{status}')
def api_keys_by_status(status: str):
    keys = keys_by_status(status)
    return {
        'status': status.upper(),
        'count': len(keys),
        'keys': keys
    }
