import platform
import socket
import getpass


def scan_device():

    try:
        hostname = socket.gethostname()

    except Exception:
        hostname = "Unknown"


    try:

        operating_system = platform.system()

        os_version = platform.version()

        os_release = platform.release()

    except Exception:

        operating_system = "Unknown"

        os_version = "Unknown"

        os_release = "Unknown"


    try:

        processor = platform.processor()

    except Exception:

        processor = "Unknown"


    try:

        username = getpass.getuser()

    except Exception:

        username = "Unknown"


    device = {

        "hostname": hostname,

        "os": operating_system,

        "os_version": os_version,

        "os_release": os_release,

        "processor": processor,

        "username": username

    }


    return device


def get_device_info():

    return scan_device()


if __name__ == "__main__":

    device = get_device_info()


    print("=" * 50)

    print("CYBERGUARD AI - DEVICE INFORMATION")

    print("=" * 50)


    for key, value in device.items():

        print(f"{key}: {value}")