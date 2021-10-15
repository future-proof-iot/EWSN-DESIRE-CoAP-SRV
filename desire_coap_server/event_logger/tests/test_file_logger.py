import os

from event_logger.file_logger import FileEventLogger, FileEvent


def test_file_event_logger():
    flog = FileEventLogger("file:./log-tmp.txt")
    print(f"flog={flog}")
    flog.connect()
    data = '{"epoch":332,"pets":[{"pet":{"etl":"vwqMHjrpYru3s3BhZJqNpdv7yVTcukv9j22PNHEzSkI=","rtl":"UFGTQCsxu3f7l2QsKwpnimSW1vfuBBp3C2C8rdAmg14=","exposure":780,"req_count":432,"avg_d_cm":151}},{"pet":{"etl":"2IDGdmnLl2JDBRxfjVsC5MMqMdA1lGjlqzUjnlmS9Ew=","rtl":"EDfFx+xAXrsAaIJaNbUgdVFf0WTktZIiyJwzhF7dqBQ=","exposure":640,"req_count":323,"avg_d_cm":71}}]}'
    flog.log("/dwmCAFE/ertl", data)
    flog.disconnect()
    # parse log file
    handle = open(flog.path, "r")
    line = handle.readline()
    print(f"line={line}")
    print(FileEvent.from_str(line))
    handle.close()
    # delete log_file
    os.remove(flog.path)
