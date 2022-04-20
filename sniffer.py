import subprocess
import redis
import logging

logger = logging.getLogger(__name__)

f_handler = logging.FileHandler("sniffer.log")
f_handler.setLevel(logging.ERROR)

f_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
f_handler.setFormatter(f_format)

logger.addHandler(f_handler)

result = subprocess.Popen(
    ["socat", "-x", "TCP-LISTEN:5003,reuseaddr,fork,nodelay", "FILE:/dev/ttyUSB0,b115200"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)

r = redis.Redis(host="10.0.38.46")

print_next = False
while True:
    bytes_input = []
    while len(bytes_input) < 6:
        line = result.stderr.readline().decode()
        if line[0] in ["<", ">"]:
            continue
        bytes_input += line.replace("\n", "").split(" ")[1:]
        print("INPUT: ", bytes_input)
        print(line)

    if bytes_input == ["01", "10", "00", "01", "01", "ed"]:
        print(line, "^-------------")
        print_next = True
    else:
        continue

    bytes_read = []
    if print_next:
        while len(bytes_read) < 7:
            line = result.stderr.readline().decode()
            if line[0] in ["<", ">"]:
                continue
            bytes_read += line.replace("\n", "").split(" ")[1:]
            print("OUTPUT: ", bytes_read)

        try:
            data_index = bytes_read.index("02") + 1
            raw = int("".join(bytes_read[data_index : data_index + 2]), 16) / 100
            temp = -8688.0973066898 * (
                (2.301999 * 10 ** -4 * (-0.388 * raw - 0.0300) + 0.15274808) ** 0.5 - 0.39083
            )
            r.hset("mbtemp_sniffer", 1, temp)
            if temp > 27.5 or temp < 26:
                logger.error(
                    "Abnormal temperature reading, with the following byte values: {}".format(
                        str(line)
                    )
                )
        except ValueError:
            logger.error(
                "Failed temperature reading, with the following byte values: {}".format(str(line))
            )

        print_next = False
