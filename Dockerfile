FROM ubuntu:16.04
RUN apt-get update && apt-get install wget sudo -y
RUN wget -qO- https://get.haskellstack.org/ | sh
RUN stack setup --install-ghc --resolver=lts-12.11
RUN stack install hlint --resolver=lts-12.11