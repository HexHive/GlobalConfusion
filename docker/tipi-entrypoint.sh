#!/usr/bin/env bash

set -ue

DEBUG=0

unset PYTHONPATH

IN=${IN:-/data}
echo $@
TA=${1}
TEE=${2}
TIMEOUT=${3:-180}
TA_PATH="${IN}/new/${TA}"

OUT=${OUT:-/data}
OUTDIR=${OUT}/${TA}
PROJECT="GhidraProject"

GHIDRA=/ghidra

# keep track of time
mkdir -p /data/analysis/${TA}
echo '{"ghidra_start": '$(date +%s )'}' > /data/analysis/${TA}/report.json

if [[ ${DEBUG} -eq 1 ]]; then
  # run in debug mode
  GHIDRA_PROJ=${OUT}
  if [ -f "${OUT}/imported/${TA}" ]; then
    # project already exists, use `-process`
    timeout ${TIMEOUT} ${GHIDRA}/support/analyzeHeadless \
                ${GHIDRA_PROJ} \
                ${PROJECT} \
                -scriptPath /src/ghidra_scripts/ \
                -preScript FunctionIDHeadlessPrescript.java \
                -process ${TA} \
                -noanalysis \
                -postScript tipi.py \
                ++tee ${TEE}
  else
    # project does not exist yet, use `-import`

    # We move the binary to ${OUT}/imported upfront so that the path to the
    # executable stays stable. For instance calls to program.getExecutablePath()
    # in Ghidra are still valid.
    mv ${OUT}/new/${TA} ${OUT}/imported/
    TA_PATH=${OUT}/imported/${TA}
    timeout ${TIMEOUT} ${GHIDRA}/support/analyzeHeadless \
                ${GHIDRA_PROJ} \
                ${PROJECT} \
                -import ${TA_PATH} \
                -scriptPath /src/ghidra_scripts/ \
                -preScript FunctionIDHeadlessPrescript.java \
                -postScript tipi.py \
                ++tee ${TEE}
    # TODO: analyzeHeadless does not return proper error codes when the import
    #       fails. Thus, we need to manually copy the binary back to ${OUT}/new.
    #       Find a way to do this automatically.
  fi
else
  # run in production mode
  GHIDRA_PROJ=/tmp/ghidraproj
  mkdir -p ${GHIDRA_PROJ}
  timeout ${TIMEOUT} ${GHIDRA}/support/analyzeHeadless \
              $GHIDRA_PROJ \
              SharingCaringTmpProj \
              -import ${TA_PATH} \
              -scriptPath /src/ghidra_scripts/ \
              -preScript FunctionIDHeadlessPrescript.java \
              -postScript tipi.py \
              ++tee ${TEE}
              #-deleteProject
fi

chmod +x /data/analysis
chmod +x /data/analysis/*
chmod o+r+w -R /data/analysis
