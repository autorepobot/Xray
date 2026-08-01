package splithttp

import (
	"strings"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
)

const minH3BrutalRate = 65536

func validateH3Congestion(quicParams *internet.QuicParams) error {
	if quicParams == nil {
		return nil
	}

	switch strings.ToLower(quicParams.Congestion) {
	case "", "bbr":
		if _, err := bbr.ParseProfile(quicParams.BbrProfile); err != nil {
			return errors.New("invalid XHTTP/3 BBR profile").Base(err)
		}
		return nil
	case "reno":
		return nil
	case "force-brutal":
		if quicParams.BrutalUp < minH3BrutalRate {
			return errors.New("XHTTP/3 force-brutal requires brutalUp of at least ", minH3BrutalRate, " bytes per second")
		}
		return nil
	case "brutal":
		return errors.New("XHTTP/3 does not support congestion control brutal without bandwidth negotiation; use reno, bbr, or force-brutal")
	default:
		return errors.New("unsupported XHTTP/3 congestion control ", quicParams.Congestion)
	}
}

func configureH3Congestion(conn *quic.Conn, quicParams *internet.QuicParams) error {
	if err := validateH3Congestion(quicParams); err != nil {
		return err
	}
	if quicParams == nil {
		quicParams = &internet.QuicParams{}
	}

	switch strings.ToLower(quicParams.Congestion) {
	case "reno":
		return nil
	case "force-brutal":
		congestion.UseBrutal(conn, quicParams.BrutalUp)
		return nil
	default: // empty and bbr
		profile, _ := bbr.ParseProfile(quicParams.BbrProfile)
		congestion.UseBBR(conn, profile)
		return nil
	}
}
