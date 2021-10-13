FROM rust:latest
WORKDIR /quilkin
# How to install quilkin
ARG install_args="--git https://github.com/googleforgames/quilkin quilkin"
RUN apt update && apt install -y iperf3 socat
RUN cargo install $install_args
COPY ./run.sh /quilkin
COPY ./proxy.yaml /quilkin/quilkin.yaml
CMD ["/quilkin/run.sh"]
