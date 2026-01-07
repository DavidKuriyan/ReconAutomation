package bus

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

type RedisClient struct {
	client *redis.Client
	ctx    context.Context
}

func NewRedisClient(addr string) (*RedisClient, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr: addr,
	})

	ctx := context.Background()
	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		return nil, err
	}

	return &RedisClient{
		client: rdb,
		ctx:    ctx,
	}, nil
}

func (r *RedisClient) Publish(channel, message string) error {
	return r.client.Publish(r.ctx, channel, message).Err()
}

func (r *RedisClient) Subscribe(channel string, handler func(string)) error {
	pubsub := r.client.Subscribe(r.ctx, channel)
	_, err := pubsub.Receive(r.ctx)
	if err != nil {
		return err
	}

	go func() {
		ch := pubsub.Channel()
		for msg := range ch {
			handler(msg.Payload)
		}
	}()

	return nil
}

func (r *RedisClient) Close() error {
	return r.client.Close()
}
