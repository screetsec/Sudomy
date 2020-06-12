FROM alpine:3.9 AS builder
LABEL maintainer="myugan59@gmail.com"

ENV GOROOT=/usr/lib/go GOPATH=/go PATH=/go/bin:$PATH PHANTOMJS_VERSION=2.1.1 PATH="$PATH:/usr/lib/sudomy"

RUN apk add --no-cache git make musl-dev go bash util-linux py-pip nmap bind-tools jq curl grep chromium-chromedriver  nodejs nodejs-npm && \
    rm -rf /var/cache/apk/* && \
    mkdir -p ${GOPATH}/src ${GOPATH}/bin && \
    go get github.com/tomnomnom/httprobe && \
    go get github.com/OJ/gobuster && \
    # Install PhantomJS
    curl -k -Ls https://bitbucket.org/ariya/phantomjs/downloads/phantomjs-${PHANTOMJS_VERSION}-linux-x86_64.tar.bz2 | tar -jxvf - -C / && \
    cp phantomjs-${PHANTOMJS_VERSION}-linux-x86_64/bin/phantomjs /usr/local/bin/phantomjs && \
    rm -fR phantomjs-${PHANTOMJS_VERSION}-linux-x86_64

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

FROM builder

# sudomy.api variables
ENV SHODAN_API="" CENSYS_API="" CENSYS_SECRET="" VIRUSTOTAL="" BINARYEDGE="" SECURITY_TRAILS=""

RUN apk del make musl-dev gcc && \
    rm -rf /var/cache/apk/* && \
    # Install wappalyzer & wscat
    npm config set unsafe-perm true && \
    npm i -g wappalyzer wscat && \
    git clone https://github.com/Screetsec/Sudomy.git /usr/lib/sudomy

WORKDIR /usr/lib/sudomy
COPY --from=builder /app/ ./

VOLUME ["/usr/lib/sudomy"]

CMD ["--help"]
ENTRYPOINT ["sudomy"]