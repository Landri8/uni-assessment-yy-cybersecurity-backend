import redis

r = redis.Redis(host='localhost', port=6379, db=0)

try:
    r.ping()  # This will check the connection
    print("Connected to Redis")
except redis.ConnectionError:
    print("Redis connection failed")