package main_test

import (
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"code.cloudfoundry.org/gorouter/config"
	"code.cloudfoundry.org/gorouter/routeservice"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("modifications of X-Forwarded-Client-Cert", func() {
	var testState *testState

	BeforeEach(func() {
		testState = NewTestState()
	})

	AfterEach(func() {
		if testState != nil {
			testState.StopAndCleanup()
		}
	})

	type gorouterConfig struct {
		forwardedClientCert string
	}

	type clientConfig struct {
		clientRequestScheme string
		clientCert          bool
		clientXFCC          bool

		expectedXFCC string
	}

	testCases := map[gorouterConfig][]clientConfig{
		{config.ALWAYS_FORWARD}: {
			// | scheme | clientCert | clientXFCC | expectedXFCC |
			// |--------|------------|------------|--------------|
			{"http", false, false, "clientXFCC"},
			{"http", false, true, "clientXFCC"},
			{"https", false, false, "clientXFCC"},
			{"https", false, true, "clientXFCC"},
			{"https", true, false, "clientXFCC"},
			{"https", true, true, "clientXFCC"},
		},
		{config.FORWARD}: {
			// | scheme | clientCert | clientXFCC | expectedXFCC |
			// |--------|------------|------------|--------------|
			{"http", false, false, ""},
			{"http", false, true, ""},
			{"https", false, false, ""},
			{"https", false, true, ""},
			{"https", true, false, "clientXFCC"},
			{"https", true, true, "clientXFCC"},
		},
		{config.SANITIZE_SET}: {
			// | scheme | clientCert | clientXFCC | expectedXFCC |
			// |--------|------------|------------|--------------|
			{"http", false, false, ""},
			{"http", false, true, ""},
			{"https", false, false, ""},
			{"https", false, true, ""},
			{"https", true, false, "clientCert"},
			{"https", true, true, "clientCert"},
		},
	}
	for gc, cc := range testCases {
		gorouterCfg := gc
		clientCfgs := cc

		for i, clientCfg := range clientCfgs {
			It(fmt.Sprintf(
				"supports requests via a route service:\n\tforwarded_client_cert == %s\n\tclient request scheme: %s\n\tclient cert: %t\n\tclient XFCC header: %t\n",
				gorouterCfg.forwardedClientCert,
				clientCfg.clientRequestScheme,
				clientCfg.clientCert,
				clientCfg.clientXFCC,
			), func() {
				testState.cfg.ForwardedClientCert = gorouterCfg.forwardedClientCert
				testState.cfg.EnableSSL = true
				testState.cfg.ClientCertificateValidationString = "request"

				testState.StartGorouter()

				doRequest := func(scheme, hostname string, addXFCCHeader bool) {
					req := testState.newRequest(fmt.Sprintf("%s://%s", scheme, hostname))
					if addXFCCHeader {
						req.Header.Add("X-Forwarded-Client-Cert", "some-client-xfcc")
					}
					resp, err := testState.client.Do(req)
					Expect(err).NotTo(HaveOccurred())
					Expect(resp.StatusCode).To(Equal(200))
					resp.Body.Close()
				}
				appHostname := fmt.Sprintf("basic-app-%d-via-internal-route-service.some.domain", i)
				appReceivedHeaders := make(chan http.Header, 1)
				testApp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					appReceivedHeaders <- r.Header
					w.WriteHeader(200)
				}))
				defer testApp.Close()

				routeServiceReceivedHeaders := make(chan http.Header, 1)
				routeService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					routeServiceReceivedHeaders <- r.Header
					w.WriteHeader(200)

					url := r.Header.Get(routeservice.HeaderKeyForwardedURL)
					newRequest := testState.newRequest(url)
					for k, v := range r.Header {
						newRequest.Header[k] = v
					}
					resp, err := http.DefaultClient.Do(newRequest)
					Expect(err).NotTo(HaveOccurred())
					defer resp.Body.Close()
				}))
				defer routeService.Close()

				testState.registerWithInternalRouteService(testApp, routeService, appHostname)

				if clientCfg.clientCert {
					testState.client.Transport.(*http.Transport).TLSClientConfig.Certificates = testState.trustedClientTLSConfig.Certificates
				}
				doRequest(clientCfg.clientRequestScheme, appHostname, clientCfg.clientXFCC)

				switch clientCfg.expectedXFCC {
				case "":
					Expect(<-routeServiceReceivedHeaders).NotTo(HaveKey("X-Forwarded-Client-Cert"))
					Expect(<-appReceivedHeaders).NotTo(HaveKey("X-Forwarded-Client-Cert"))
				case "clientXFCC":
					Expect((<-routeServiceReceivedHeaders).Get("X-Forwarded-Client-Cert")).To(Equal("some-client-xfcc"))
					Expect((<-appReceivedHeaders).Get("X-Forwarded-Client-Cert")).To(Equal("some-client-xfcc"))
				case "clientCert":
					Expect((<-routeServiceReceivedHeaders).Get("X-Forwarded-Client-Cert")).To(Equal(
						sanitize(testState.trustedClientTLSConfig.Certificates[0]),
					))
					Expect((<-appReceivedHeaders).Get("X-Forwarded-Client-Cert")).To(Equal(
						sanitize(testState.trustedClientTLSConfig.Certificates[0]),
					))
				}
			})
		}
	}
})

func sanitize(cert tls.Certificate) string {
	b := pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}
	certPEM := pem.EncodeToMemory(&b)
	s := string(certPEM)
	r := strings.NewReplacer("-----BEGIN CERTIFICATE-----", "",
		"-----END CERTIFICATE-----", "",
		"\n", "")
	return r.Replace(s)
}
