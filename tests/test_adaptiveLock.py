import pytest
import time
from unittest.mock import MagicMock, patch, call

from src.adaptive_lockout import AdaptiveLockout

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_db():
    """
    Creates a mock DatabaseManager with necessary methods stubbed.
    """
    db = MagicMock()

    # DB-layer methods used by AdaptiveLockout
    db.record_lockout_failure.return_value = None
    db.clear_lockout_history.return_value = None

    # Default: no failures returned
    db.get_lockout_history.return_value = []

    # Mock connection context manager for trimming logic
    conn = MagicMock()
    db.connect.return_value = conn
    conn.execute.return_value = None
    conn.commit.return_value = None
    conn.rollback.return_value = None

    return db

# ---------------------------------------------------------------------------
# 1. Initialization & Config Validation
# ---------------------------------------------------------------------------

def test_init_with_defaults(mock_db):
    """Test initialization with empty config uses class defaults."""
    al = AdaptiveLockout(mock_db, {})
    assert al.max_delay == AdaptiveLockout.DEFAULT_MAX_DELAY
    assert al.history_window == AdaptiveLockout.DEFAULT_HISTORY_WINDOW
    assert al.trim_limit == AdaptiveLockout.DEFAULT_TRIM_LIMIT

def test_init_handles_none_config(mock_db):
    """Test initialization with config=None defaults to empty dict."""
    al = AdaptiveLockout(mock_db, None)
    assert al.max_delay == AdaptiveLockout.DEFAULT_MAX_DELAY

def test_init_with_custom_valid_config(mock_db):
    """Test initialization with valid custom values."""
    cfg = {
        "max_lockout_delay": 42,
        "history_window_seconds": 60,
        "history_trim_limit": 10,
    }
    al = AdaptiveLockout(mock_db, cfg)
    assert al.max_delay == 42
    assert al.history_window == 60
    assert al.trim_limit == 10

@pytest.mark.parametrize("bad_cfg", [
    {"max_lockout_delay": "x"},
    {"history_window_seconds": None},
    {"history_trim_limit": 1.5},
])
def test_init_rejects_non_integer_config(mock_db, bad_cfg):
    """Test that non-integer values raise ValueError."""
    with pytest.raises(ValueError, match="must be integers"):
        AdaptiveLockout(mock_db, bad_cfg)

@pytest.mark.parametrize("bad_cfg", [
    {"max_lockout_delay": -1},
    {"history_window_seconds": 0},
    {"history_trim_limit": 0},
])
def test_init_rejects_non_positive_config(mock_db, bad_cfg):
    """Test that negative or zero values raise ValueError."""
    with pytest.raises(ValueError, match="must be positive"):
        AdaptiveLockout(mock_db, bad_cfg)

# ---------------------------------------------------------------------------
# 2. Record Failure (DB Interactions)
# ---------------------------------------------------------------------------

def test_record_failure_calls_db_and_trims(mock_db):
    """Test that recording a failure calls the DB and executes the trimming SQL."""
    trim_limit = 50
    al = AdaptiveLockout(mock_db, {"history_trim_limit": trim_limit})
    
    al.record_failure()

    # 1. Verify standard DB record call
    mock_db.record_lockout_failure.assert_called_once()
    
    # 2. Verify connection handling
    mock_db.connect.assert_called_once()
    conn = mock_db.connect.return_value
    
    # 3. Verify SQL execution and parameters
    conn.execute.assert_called_once()
    args, _ = conn.execute.call_args
    sql_query = args[0]
    sql_params = args[1]
    
    assert "DELETE FROM lockout_attempts" in sql_query
    assert "LIMIT -1 OFFSET ?" in sql_query
    assert sql_params == (trim_limit,)
    
    conn.commit.assert_called_once()

def test_record_failure_rolls_back_on_error(mock_db):
    """Test transaction rollback if trimming fails."""
    al = AdaptiveLockout(mock_db, {})
    conn = mock_db.connect.return_value
    conn.execute.side_effect = Exception("db fail")

    with pytest.raises(Exception, match="db fail"):
        al.record_failure()

    conn.rollback.assert_called_once()

# ---------------------------------------------------------------------------
# 3. Check and Delay Logic
# ---------------------------------------------------------------------------

def test_check_and_delay_no_failures_allows(mock_db):
    """If history is empty, allow immediately."""
    al = AdaptiveLockout(mock_db, {})
    allowed, delay = al.check_and_delay()

    assert allowed is True
    assert delay == 0

@patch("time.time", return_value=1000)
def test_single_failure_allows_immediately(mock_time, mock_db):
    """
    1 failure = count 1. 
    exp = count - 1 = 0.
    2^0 = 1 second delay.
    If 1 second has passed, it should allow.
    """
    # Last attempt was exactly 1 second ago (999)
    mock_db.get_lockout_history.return_value = [999]

    al = AdaptiveLockout(mock_db, {})
    allowed, delay = al.check_and_delay()

    # Delay calculated is 1s. Elapsed is 1s. Remaining is 0.
    assert allowed is True
    assert delay == 0

@patch("time.time", return_value=1000)
def test_two_failures_enforces_delay(mock_time, mock_db):
    """
    2 failures = count 2.
    exp = 1 -> 2^1 = 2 seconds delay.
    Last attempt was 1 second ago (999).
    Remaining should be 1 second.
    """
    mock_db.get_lockout_history.return_value = [900, 999]

    al = AdaptiveLockout(mock_db, {})
    allowed, delay = al.check_and_delay()

    assert allowed is False
    assert delay == 1

@patch("time.time", return_value=1000)
def test_exponential_growth(mock_time, mock_db):
    """
    5 failures. exp = 4 -> 2^4 = 16s delay.
    Last attempt just happened (1000).
    """
    mock_db.get_lockout_history.return_value = [900, 910, 920, 930, 1000]

    al = AdaptiveLockout(mock_db, {})
    allowed, delay = al.check_and_delay()

    assert allowed is False
    assert delay == 16

@patch("time.time", return_value=1000)
def test_delay_capped_by_max_delay(mock_time, mock_db):
    """Test that delay never exceeds configured max_lockout_delay."""
    # 50 failures would be 2^49 (massive), but max is 30
    # FIX: Ensure last attempt is AT current time (1000) so elapsed=0, remaining=30
    mock_db.get_lockout_history.return_value = list(range(950, 1001))

    al = AdaptiveLockout(mock_db, {"max_lockout_delay": 30})
    allowed, delay = al.check_and_delay()

    assert allowed is False
    assert delay == 30

@patch("time.time", return_value=1000)
def test_history_window_filtering(mock_time, mock_db):
    """Test that failures older than the window are ignored."""
    # DB mock returns nothing, simulating the query 'since_timestamp=cutoff'
    mock_db.get_lockout_history.return_value = []

    al = AdaptiveLockout(mock_db, {"history_window_seconds": 10})
    allowed, delay = al.check_and_delay()

    # The logic inside check_and_delay calls db.get_lockout_history(since_timestamp=...)
    # verify the arg passed to DB
    cutoff = 1000 - 10 # 990
    mock_db.get_lockout_history.assert_called_with(since_timestamp=990)
    
    assert allowed is True

@patch("time.time", return_value=1000)
def test_boundary_exact_expiration(mock_time, mock_db):
    """
    Test the exact second the delay expires.
    2 failures -> 2s delay.
    Last attempt at 998 (1000 - 998 = 2s elapsed).
    Remaining = 2 - 2 = 0. Should be allowed.
    """
    mock_db.get_lockout_history.return_value = [900, 998]
    al = AdaptiveLockout(mock_db, {})
    
    allowed, delay = al.check_and_delay()
    
    assert allowed is True
    assert delay == 0

@patch("time.time", return_value=1000)
def test_massive_failure_count_internal_cap(mock_time, mock_db):
    """
    Test extremely high failure count to ensure internal logic (max_exp) 
    prevents overflow errors before max_delay capping applies.
    """
    # 100 failures
    mock_db.get_lockout_history.return_value = [1000] * 100
    
    # Set a huge max delay to see if the internal exponents explode
    # 2^31 is the internal cap in the code
    huge_delay = 2**33 
    al = AdaptiveLockout(mock_db, {"max_lockout_delay": huge_delay})
    
    allowed, delay = al.check_and_delay()
    
    assert allowed is False
    # The code caps exponent at 31, so delay should be 2^31 (approx 2 billion)
    # 2**31 = 2147483648
    assert delay == 2**31

# ---------------------------------------------------------------------------
# 4. Session Reset
# ---------------------------------------------------------------------------

def test_reset_session_clears_history(mock_db):
    """Test that resetting the session calls the DB clear method."""
    al = AdaptiveLockout(mock_db, {})
    al.reset_session()

    mock_db.clear_lockout_history.assert_called_once()

# ---------------------------------------------------------------------------
# 5. Status Messaging
# ---------------------------------------------------------------------------

@patch("time.time", return_value=1000)
def test_status_message_structure_locked(mock_time, mock_db):
    """Test status message when user is currently blocked."""
    # 3 failures -> 4s delay. Last attempt at 999.
    # Elapsed 1s. Remaining 3s.
    mock_db.get_lockout_history.return_value = [900, 910, 999]

    al = AdaptiveLockout(mock_db, {})
    status = al.get_status_message()

    assert status["allowed"] is False
    assert status["delay"] == 3
    assert status["failures"] == 3

@patch("time.time", return_value=1000)
def test_status_message_structure_allowed(mock_time, mock_db):
    """Test status message when user is allowed."""
    mock_db.get_lockout_history.return_value = []

    al = AdaptiveLockout(mock_db, {})
    status = al.get_status_message()

    assert status["allowed"] is True
    assert status["delay"] == 0
    assert status["failures"] == 0