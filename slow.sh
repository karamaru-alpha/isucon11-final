#!/bin/sh

sudo pt-query-digest $1 --report-format=query_report --limit=8 # --filter='$event->{arg} =~ m/^select/i' --limit=5
