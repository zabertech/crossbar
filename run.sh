#!/bin/bash

# If file based logging is desired, use 
# LOG_TO_FILE=/path/to/file run.sh

IMAGE_NAME=${IMAGE_NAME:=izaber/nexus}
CONTAINER_NAME=${CONTAINER_NAME:=nexus}
CBDIR=${CBDIR:=/app/data}
LOG_LEVEL=${LOG_LEVEL:=debug}
LOG_COLOURS=${LOG_COLOURS:=true}
LOG_FORMAT=${LOG_FORMAT:=standard}
PORT_PLAINTEXT=${PORT_PLAINTEXT:=8282}
PORT_SSL=${PORT_SSL:=4430}

# Usually the the system will be in --rm
# However when we do a launch/run we will start it
# in -d --restart mode
LAUNCH_MODE=${LAUNCH_MODE:=--rm}

help () {
cat << HELP
Usage: run.sh [COMMAND] [ARGUMENTS]...
Performs various for nexus servers including building images, launching and debugging support

COMMANDS:

  If no command is provided, the script will build, configure, and launch an instance of
    the nexus container.

  help
        This help text

  build
        Forces a build of the container

  stop
        docker stop $CONTAINER_NAME

  here
        This will launch the nexus in the current environment without using docker
        Useful when you're in the container itself or are developing locally

  login
        This runs docker exec -ti $CONTAINER_NAME bash to allow "logging in" to a container
      
  root
        This runs docker exec -ti -u root $CONTAINER_NAME bash to allow "logging in" to a
            container as root

  If the command does not match any of the listed commands, the system will instantiate the
  container then pass the entire set of arguments to be invoked in the new container.

HELP
}

# Please do not change the default behaviour of logging
# In fact, the system uses invoke.sh to capture the 
# stdout and stderr for dumping into the ./logs directory
# automatically via tee.
LOG_TO_FILE=${LOG_TO_FILE:=''}

build_docker_image () {
  echo "Creating the ${IMAGE_NAME} docker image"
  docker build -t $IMAGE_NAME .
}

upsert_docker_image () {
  if [[ "$(docker images -q ${IMAGE_NAME} 2> /dev/null)" == "" ]]; then
    build_docker_image
  fi
}

prepare_environment () {
  if [ ! -f data/izaber.yaml ]; then
    echo "Copying over data/config.yaml.example to data/config.yaml"
    cp data/izaber.yaml.example data/izaber.yaml
  fi
}

default_invoke_command () {
  INVOKE_COMMAND="/app/run-server.sh"
  #INVOKE_COMMAND="tmux new -s nexus /app/run-server.sh"
}

launch_container () {
  text=$(sed 's/[[:space:]]\+/ /g' <<< ${INVOKE_COMMAND})
  echo "Invoking: ${text}"

  CMD="docker run --name $CONTAINER_NAME \
      -ti \
      -v `pwd`/logs:/logs \
      -v `pwd`:/app \
      -p $PORT_PLAINTEXT:8282 \
      -p $PORT_SSL:8181 \
      $LAUNCH_MODE \
      $IMAGE_NAME $INVOKE_COMMAND"
  echo -e "Starting container ${CONTAINER_NAME} with command:\n$CMD\n"
  $CMD
}

login() {
  if [[ "$(docker inspect ${CONTAINER_NAME} 2> /dev/null)" == "[]" ]]; then
    upsert_docker_image
    INVOKE_COMMAND="/bin/bash"
    launch_container
  else
    docker exec -ti $CONTAINER_NAME /bin/bash
  fi
}

# Basic stuff
prepare_environment

if [ $# -eq 0 ]; then
  upsert_docker_image
  default_invoke_command
  launch_container
else
  case $1 in
    -h) help
        ;;
    --help) help
        ;;
    help) help
        ;;

    build) build_docker_image
        ;;

    stop) docker stop $CONTAINER_NAME
        ;;

    here) default_invoke_command
          cd /app/data
          $INVOKE_COMMAND
        ;;

    login) login
        ;;

    root) docker exec -ti -u root $CONTAINER_NAME /bin/bash
        ;;

    *) upsert_docker_image
       INVOKE_COMMAND="$@"
       LAUNCH_MODE="-d --restart always"
       launch_container
       ;;
  esac
fi

