FROM alpine:3.9 AS builder
LABEL maintainer="myugan59@gmail.com"
ENV GOROOT=/usr/lib/go GOPATH=/go PATH=/go/bin:$PATH

RUN apk add --no-cache git make musl-dev go bash bash-doc bash-completion py-pip nmap bind-tools jq curl grep nano && \
    rm -rf /var/cache/apk/* && \
    mkdir -p ${GOPATH}/src ${GOPATH}/bin && \
    go get github.com/tomnomnom/httprobe && \
    go get github.com/OJ/gobuster

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

FROM builder

# Create user
RUN git clone https://github.com/Screetsec/Sudomy.git /usr/lib/sudomy

WORKDIR /usr/lib/sudomy
COPY --from=builder /app/ ./

VOLUME ["/usr/lib/sudomy"]
ENTRYPOINT [ "/usr/lib/sudomy/sudomy" ]
CMD ["--help"]
