
import pytest

from observatory.runtime.docker_runtime import DockerRuntime, DockerRuntimeError


@pytest.fixture(scope="module")
def runtime():
    instance = DockerRuntime(timeout_seconds=10)

    try:
        instance.check_available()
    except DockerRuntimeError as exc:
        pytest.skip(str(exc))

    return instance


def test_container_executes_python_and_captures_output(runtime):
    result = runtime.run_python("print('observatory-runtime-ok')")

    assert result.exit_code == 0
    assert "observatory-runtime-ok" in result.output
    assert result.timed_out is False


def test_container_captures_failed_execution(runtime):
    result = runtime.run_python("raise SystemExit(7)")

    assert result.exit_code == 7
    assert result.timed_out is False


def test_empty_source_is_rejected():
    runtime = DockerRuntime()

    with pytest.raises(ValueError, match="source must not be empty"):
        runtime.run_python("   ")
