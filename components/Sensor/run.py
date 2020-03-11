from Sensor import Sensor

if __name__ == "__main__":
    sensor = Sensor()
    s = sensor.create_socket()
    sensor.listen_on_socket(s)