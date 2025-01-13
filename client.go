package go_katran

import "log"

type Client struct{}

func (client *Client) Hello() {
	log.Print("hello")
}
