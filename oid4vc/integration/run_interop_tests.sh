#!/usr/bin/env bash

F=docker-compose.interop.yml

ARG=$1
shift

case $ARG in
  help)
    echo "USAGE: ./run_interop_tests [down|build|logs|...]"
    echo "  Passing no args will down, build, and run tests"
    echo "  Args besides down/build/logs will be passed to the test"
    echo "  invocation, e.g.:"
    echo "    docker-compose run tests $@"
    ;;
  down)
    docker-compose -f $F down -v
    ;;

  build)
    docker-compose -f $F build
    ;;

  logs)
    docker-compose -f $F logs "$@" | less -R
    ;;

  *)
    docker-compose -f $F down -v
    docker-compose -f $F build
    docker-compose -f $F run tests -m interop "$ARG" "$@"
    ;;
esac
