FROM chromedp/headless-shell:latest AS builder

ENV PHANTOMJS_VERSION=2.1.1 PATH="$PATH:/usr/lib/sudomy"
RUN apt update \
    && apt install -y --no-install-recommends git \
    apt-transport-https \
    bzip2 \
    nmap \
    jq \
    curl \
    python3 \
    python3-pip \
    make \
    musl-dev \
    dnsutils \
    wget \
	parallel \
	grep \
    bsdmainutils \
    # Install NodeJS 10.x
    && curl -sL https://deb.nodesource.com/setup_10.x -o setup.sh \
    && bash setup.sh \
    && apt install -y nodejs \
    # Install PhantomJS
    && curl -k -Ls https://bitbucket.org/ariya/phantomjs/downloads/phantomjs-${PHANTOMJS_VERSION}-linux-x86_64.tar.bz2 | tar -jxvf - -C / && \
    cp phantomjs-${PHANTOMJS_VERSION}-linux-x86_64/bin/phantomjs /usr/local/bin/phantomjs \
    && rm -fR phantomjs-${PHANTOMJS_VERSION}-linux-x86_64 \
    && rm -rf /var/lib/apt/lists/* \
    && wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && echo 'deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main' | tee /etc/apt/sources.list.d/google-chrome.list \
    && apt-get update \
    && apt-get install google-chrome-stable -y \
    && pip3 install --upgrade setuptools wheel

WORKDIR /app
COPY requirements.txt .
RUN pip3 install -r requirements.txt

FROM builder
ENV PATH "$PATH:/usr/lib/sudomy/lib/bin"
ENV SHODAN_API="" CENSYS_API="" CENSYS_SECRET="" VIRUSTOTAL="" BINARYEDGE="" SECURITY_TRAILS="" DNSDB_API="" PASSIVE_API="" SPYSE_API="" FACEBOOK_TOKEN="" YOUR_WEBHOOK_URL=""
RUN npm config set unsafe-perm true \
    # Install wappalyzer & wscat
    && npm i -g wappalyzer wscat

ADD . /usr/lib/sudomy
WORKDIR /usr/lib/sudomy
COPY --from=builder /app/ ./

VOLUME ["/usr/lib/sudomy"]

CMD ["--help"]
ENTRYPOINT ["sudomy"]
