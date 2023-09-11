import time
import datetime

def get_time(timestamp):
    datetime_obj = datetime.datetime.fromtimestamp(timestamp)

    return datetime_obj.strftime("%d-%m-%Y %H:%M")

if __name__ == '__main__':
    times = time.time()
    print(get_time(times))