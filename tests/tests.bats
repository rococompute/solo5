#!/usr/bin/env bats
# Copyright (c) 2015-2020 Contributors as noted in the AUTHORS file
#
# This file is part of Solo5, a sandboxed execution environment.
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
# AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
# CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
# OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

fatal()
{
  echo "ERROR: $@" 1>&2
  exit 1
}

setup() {
  cd ${BATS_TEST_DIRNAME}

  MAKECONF=../Makeconf.sh
  [ ! -f ${MAKECONF} ] && fatal "Can't find Makeconf.sh, looked in ${MAKECONF}"
  source ${MAKECONF}

  if [ -x "$(command -v timeout)" ]; then
    TIMEOUT=timeout
  elif [ -x "$(command -v gtimeout)" ]; then
    TIMEOUT=gtimeout
  else
    fatal "timeout(gtimeout) is required"
  fi
  if [ -x "$(command -v seq)" ]; then
    SEQ=seq
  elif [ -x "$(command -v gseq)" ]; then
    SEQ=gseq
  else
    fatal "seq(gseq) is required"
  fi

  case "${BATS_TEST_NAME}" in
  *hvt)
    [ -z "${CONFIG_HVT_TENDER}" ] && skip
    case "${CONFIG_HOST}" in
    Linux)
      [ -c /dev/kvm -a -w /dev/kvm ] || skip "no access to /dev/kvm or not present"
      ;;
    FreeBSD|OpenBSD)
      # TODO, just try and run the test anyway
      ;;
    Darwin)
      [ "$(sysctl -n kern.hv_support 2>/dev/null)" = "1" ] || \
        skip "Hypervisor.framework not available (kern.hv_support != 1)"
      codesign -d --entitlements - ../tenders/hvt/solo5-hvt 2>&1 | \
        grep -q com.apple.security.hypervisor || \
        skip "solo5-hvt is not signed with the hypervisor entitlement"
      ;;
    *)
      skip "Don't know how to run ${BATS_TEST_NAME} on ${CONFIG_HOST}"
      ;;
    esac
    HVT_TENDER=../tenders/hvt/solo5-hvt
    HVT_TENDER_DEBUG=../tenders/hvt/solo5-hvt-debug
    ;;
  *virtio)
    [ -z "${CONFIG_VIRTIO}" ] && skip
    [ "${CONFIG_HOST}" = "FreeBSD" ] && \
      [ ! -x "$(command -v grub-bhyve)" ] && \
      skip "grub-bhyve not available"
    [ "${CONFIG_HOST}" = "OpenBSD" ] && skip
    VIRTIO=../scripts/virtio-run/solo5-virtio-run.sh
    ;;
  *spt)
    [ -z "${CONFIG_SPT_TENDER}" ] && skip
    SPT_TENDER=../tenders/spt/solo5-spt
    ;;
  *xen)
    [ -z "${CONFIG_XEN}" ] && skip
    [ ! -x "$(command -v xl)" ] && skip "xl not available"
    [ $(id -u) -ne 0 ] && skip "need root to run Xen tests"
    ;;
  *elftool)
    ELFTOOL=../elftool/solo5-elftool
  esac

  NET0=tap100
  NET0_IP=10.0.0.2
  NET1=tap101
  NET1_IP=10.1.0.2
  NET2=tap102
}

teardown() {
  echo "${output}"
  rm -f ${BATS_TMPDIR}/storage*.img
}

setup_block() {
  BLOCK=${BATS_TMPDIR}/storage.img
  dd if=/dev/zero of=${BLOCK} bs=4k count=1024 status=none
}

hvt_run() {
  run ${TIMEOUT} --foreground 60s "${HVT_TENDER}" --mem=4096 "$@"
}

spt_run() {
  run ${TIMEOUT} --foreground 60s "${SPT_TENDER}" --mem=2 "$@"
}

virtio_run() {
  run ${TIMEOUT} --foreground 60s ${VIRTIO} "$@"
}

xen_run() {
  # "xl create" is really amenable to automation, oh yeah!
  local TEST_DIR=$(dirname "$1")
  local TEST_NAME=$(basename "$1" .xen)
  shift
  run ${TIMEOUT} --foreground 60s \
    xl create -F -c /dev/null \
      name=\"${TEST_NAME}\" kernel=\"${TEST_DIR}/${TEST_NAME}.xen\" \
      type=\"pvh\" memory=32 cmdline=\"$@\"
}

elftool_manifest() {
  run ${ELFTOOL} gen-manifest "$1" /dev/null
}

# Given a list of arguments in the format HOST[_RELEASE], returns true iff CONFIG_HOST
# matches at least one HOST. If a RELEASE is specified, additionally checks that the
# running host kernel release (uname -r) matches RELEASE *exactly*.
match_hostrelease() {
  local arg=
  local host=
  local release=
  local found=1 # false
  for arg in "$@"; do
    release="${arg#*_}"
    if [ "${release}" = "${arg}" ]; then
      host="${arg}" # just host
      release=      # don't care about release
    else
      host="${arg%_*}" # just host
                       # release got set by the initial ${arg#*_}
    fi

    if [ "${CONFIG_HOST}" = "${host}" ]; then
      if [ -n "${release}" ]; then
        [ "$(uname -r)" = "${release}" ] && found=0 && break
      else
        found=0 && break
      fi
    fi
  done
  return ${found}
}

skip_if_host_is() {
  match_hostrelease "$@" && skip "not supported on ${CONFIG_HOST}"
}

skip_unless_host_is() {
  match_hostrelease "$@" || skip "not supported on ${CONFIG_HOST}"
}

skip_unless_root() {
  [ $(id -u) -ne 0 ] && skip "need root to run this test"
  return 0
}

expect_success() {
  [ "$status" -eq 0 ] && [[ "$output" == *"SUCCESS"* ]]
}

# Hosts without tap devices (macOS) run the net tests behind netpeer, which
# hands the tender socketpair fds @3, @4, ... and plays the pinging host.
use_netpeer() {
  [ "${CONFIG_HOST}" = "Darwin" ]
}

netpeer_hvt_run() {
  local netpeer_args=()
  while [ "$1" != "--" ]; do netpeer_args+=("$1"); shift; done
  shift
  run ${TIMEOUT} --foreground 60s netpeer/netpeer "${netpeer_args[@]}" -- \
    "${HVT_TENDER}" --mem=4096 "$@"
}

guest_mem_mb() {
  echo "$output" | sed -n 's/^Solo5: Memory map: \([0-9][0-9]*\) MB addressable.*/\1/p'
}

virtio_expect_success() {
  [ "$status" -eq 0 -o "$status" -eq 2 -o "$status" -eq 83 ] && \
    [[ "$output" == *"SUCCESS"* ]]
}

expect_abort() {
  [ "$status" -eq 255 ] && [[ "$output" == *"ABORT"* ]]
}

expect_segfault() {
  [ "$status" -eq 139 ]
}

virtio_expect_abort() {
  [ "$status" -eq 0 -o "$status" -eq 2 -o "$status" -eq 83 ] && \
    [[ "$output" == *"ABORT"* ]]
}

xen_expect_abort() {
  [ "$status" -eq 0 ] && [[ "$output" == *"ABORT"* ]]
}

# ------------------------------------------------------------------------------
# Tests start here
# ------------------------------------------------------------------------------

@test "noexec host" {
  # Here be dragons.
  run test_hello/test_hello.hvt
  case "${CONFIG_HOST}" in
  Linux)
    [ "$status" -eq 127 ] && ([[ "$output" == *"No such file or directory"* ]] || [[ "$output" == *"required file not found"* ]])
    ;;
  FreeBSD)
    # XXX: imgact_elf.c:load_interp() outputs the "ELF interpreter ... not
    # found" using uprintf() here, so we can't test for it. Boo.
    # Some Clang toolchains may produce generic ELF which gives "Exec format
    # error", so also test for that case (126) and treat it as success.
    [ "$status" -eq 134 ] || [ "$status" -eq 126 ]
    ;;
  OpenBSD)
    # XXX: Unclear why the "Abort trap" is not showing up in the output.
    [ "$status" -eq 134 ]
    ;;
  *)
    skip "not implemented for ${CONFIG_HOST}"
    ;;
  esac
}

@test "hello hvt" {
  hvt_run test_hello/test_hello.hvt Hello_Solo5
  expect_success
}

@test "hello virtio" {
  virtio_run test_hello/test_hello.virtio Hello_Solo5
  virtio_expect_success
}

@test "hello spt" {
  spt_run test_hello/test_hello.spt Hello_Solo5
  expect_success
}

@test "hello xen" {
  xen_run test_hello/test_hello.xen Hello_Solo5
  expect_success
}

@test "quiet hvt" {
  hvt_run -- test_quiet/test_quiet.hvt --solo5:quiet
  expect_success
  [[ "$output" != *"Solo5:"* ]]
}

@test "quiet virtio" {
  virtio_run -- test_quiet/test_quiet.virtio --solo5:quiet
  virtio_expect_success
  # XXX "Solo5: Halted" might be printed (see old version), what to test for
  # here?
}

@test "quiet spt" {
  spt_run -- test_quiet/test_quiet.spt --solo5:quiet
  expect_success
  [[ "$output" != *"Solo5:"* ]]
}

# Don't run this for now, as we have a message that is always output in
# console.c.
# @test "quiet xen" {
#   xen_run test_quiet/test_quiet.xen --solo5:quiet
#   expect_success
#   [[ "$output" != *"Solo5:"* ]]
# }

@test "output hvt" {
  hvt_run test_output/test_output.hvt Output_Solo5
  [ "$status" -eq 0 ]
}

@test "output virtio" {
  virtio_run test_output/test_output.virtio Output_Solo5
  [ "$status" -eq 0 -o "$status" -eq 2 -o "$status" -eq 83 ]
}

@test "output spt" {
  spt_run test_output/test_output.spt Output_Solo5
  [ "$status" -eq 0 ]
}

@test "output xen" {
  xen_run test_output/test_output.xen Ouput_Solo5
  [ "$status" -eq 0 ]
}

@test "globals hvt" {
  hvt_run test_globals/test_globals.hvt
  expect_success
}

@test "globals virtio" {
  virtio_run test_globals/test_globals.virtio
  virtio_expect_success
}

@test "globals spt" {
  spt_run test_globals/test_globals.spt
  expect_success
}

@test "globals xen" {
  xen_run test_globals/test_globals.xen
  expect_success
}

@test "exception hvt" {
  hvt_run test_exception/test_exception.hvt
  expect_abort
}

@test "exception virtio" {
  virtio_run test_exception/test_exception.virtio
  virtio_expect_abort
}

@test "exception spt" {
  spt_run test_exception/test_exception.spt
  [ "$status" -eq 139 ] # SIGSEGV
}

@test "exception xen" {
  xen_run test_exception/test_exception.xen
  xen_expect_abort
}

@test "zeropage hvt" {
  hvt_run test_zeropage/test_zeropage.hvt
  expect_abort
}

@test "zeropage virtio" {
  virtio_run test_zeropage/test_zeropage.virtio
  virtio_expect_abort
}

@test "zeropage spt" {
  spt_run test_zeropage/test_zeropage.spt
  [ "$status" -eq 139 ] # SIGSEGV
}

@test "zeropage xen" {
  xen_run test_zeropage/test_zeropage.xen
  xen_expect_abort
}

@test "rnow hvt" {
  skip_unless_host_is OpenBSD Darwin
  hvt_run test_rnow/test_rnow.hvt
  [ "$status" -eq 1 ] && [[ "$output" == *"host/guest translation fault"* ]]
}

@test "xnow hvt" {
  skip_unless_host_is Linux OpenBSD Darwin

  hvt_run test_xnow/test_xnow.hvt
  [ "$status" -eq 1 ] && [[ "$output" == *"host/guest translation fault"* ]]
}

@test "xnow spt" {
  spt_run test_xnow/test_xnow.spt
  [ "$status" -eq 139 ] # SIGSEGV
}

@test "xnow xen" {
  xen_run test_xnow/test_xnow.xen
  xen_expect_abort
}

@test "xnor hvt" {
  skip_unless_host_is OpenBSD Darwin
  hvt_run test_xnor/test_xnor.hvt
  [ "$status" -eq 1 ] && [[ "$output" == *"host/guest translation fault"* ]]
}

@test "rnox hvt" {
  skip_unless_host_is OpenBSD Darwin

  hvt_run test_rnox/test_rnox.hvt
  [ "$status" -eq 1 ] && [[ "$output" == *"host/guest translation fault"* ]]
}

@test "wnox hvt" {
  skip_unless_host_is OpenBSD Darwin

  hvt_run test_wnox/test_wnox.hvt
  [ "$status" -eq 1 ] && [[ "$output" == *"host/guest translation fault"* ]]
}

@test "wnox spt" {
  spt_run test_wnox/test_wnox.spt
  [ "$status" -eq 139 ] # SIGSEGV
}

@test "wnox xen" {
  xen_run test_wnox/test_wnox.xen
  xen_expect_abort
}

@test "notls hvt" {
  hvt_run test_notls/test_notls.hvt
  expect_abort
}

@test "notls virtio" {
  virtio_run test_notls/test_notls.virtio
  virtio_expect_abort
}

@test "notls spt" {
  spt_run test_notls/test_notls.spt
  expect_segfault
}

@test "notls xen" {
  xen_run test_notls/test_notls.xen
  xen_expect_abort
}

@test "tls hvt" {
  hvt_run test_tls/test_tls.hvt
  expect_success
}

@test "tls virtio" {
  virtio_run test_tls/test_tls.virtio
  virtio_expect_success
}

@test "tls spt" {
  spt_run test_tls/test_tls.spt
  expect_success
}

@test "tls xen" {
  xen_run test_tls/test_tls.xen
  expect_success
}

@test "ssp hvt" {
  hvt_run test_ssp/test_ssp.hvt
  expect_abort
}

@test "ssp virtio" {
  virtio_run test_ssp/test_ssp.virtio
  virtio_expect_abort
}

@test "ssp spt" {
  spt_run test_ssp/test_ssp.spt
  expect_abort
}

@test "ssp xen" {
  xen_run test_ssp/test_ssp.xen
  xen_expect_abort
}

@test "fpu hvt" {
  hvt_run test_fpu/test_fpu.hvt
  expect_success
}

@test "fpu virtio" {
  virtio_run test_fpu/test_fpu.virtio
  virtio_expect_success
}

@test "fpu spt" {
  spt_run test_fpu/test_fpu.spt
  expect_success
}

@test "fpu xen" {
  xen_run test_fpu/test_fpu.xen
  expect_success
}

@test "time hvt" {
  hvt_run test_time/test_time.hvt
  # XXX:
  # On Debian 10 CI nodes, this test is flaky and fails too often with
  # "slept too little". Ignore that (and only that) case.
  if [ "${CONFIG_HOST}" = "Linux" ]; then
    if gcc --version | grep -q Debian; then
      if [ "$status" -eq 1 ] && [[ "$output" == *"slept too little"* ]]; then
        skip "flaky, ignored"
      fi
    fi
  fi
  expect_success
}

@test "time virtio" {
  virtio_run test_time/test_time.virtio
  virtio_expect_success
}

@test "time spt" {
  spt_run test_time/test_time.spt
  expect_success
}

@test "time xen" {
  xen_run test_time/test_time.xen
  expect_success
}

@test "random hvt" {
  hvt_run test_random/test_random.hvt
  expect_success
  FIRST=$(echo "$output" | grep '^first: ')
  # A second boot must not repeat the first one's bytes.
  hvt_run test_random/test_random.hvt
  expect_success
  [ "$(echo "$output" | grep '^first: ')" != "${FIRST}" ]
}

@test "random --no-random hvt" {
  hvt_run --no-random -- test_random/test_random.hvt fallback
  expect_success
  [[ "$output" == *"fallback"* ]]
}

@test "random spt" {
  spt_run -- test_random/test_random.spt fallback
  expect_success
}

@test "sandbox hvt" {
  skip_unless_host_is Darwin
  setup_block
  run ${TIMEOUT} --foreground 60s sandbox_macos/sandbox_macos ${BLOCK}
  [ "$status" -eq 0 ] && [[ "$output" == *"SUCCESS"* ]]
}

# A hostile guest must be stopped by the tender and the reason reported,
# whatever it tries. See tests/test_hostile/test_hostile.c.
hostile_run() {
  REPORT=${BATS_TMPDIR}/exit-report.json
  run ${TIMEOUT} --foreground 60s "${HVT_TENDER}" --mem=32 --cpu-limit=1 \
    --exit-report=3 -- test_hostile/test_hostile.hvt "$1" 3>${REPORT}
  REPORT_JSON=$(cat ${REPORT})
  echo "exit report: ${REPORT_JSON}"
}

@test "hostile spin hvt" {
  skip_unless_host_is Darwin
  hostile_run spin
  [[ "${REPORT_JSON}" == *'"kind":"fault"'* ]]
  [[ "${REPORT_JSON}" == *'"reason":"cpu_limit"'* ]]
  [ "$status" -eq 1 ]
}

@test "hostile wfi hvt" {
  skip_unless_host_is Darwin
  hostile_run wfi
  [[ "${REPORT_JSON}" == *'"kind":"fault"'* ]]
  [[ "${REPORT_JSON}" == *'"reason":"cpu_limit"'* ]]
  [ "$status" -eq 1 ]
}

@test "hostile hvc hvt" {
  skip_unless_host_is Darwin
  hostile_run hvc
  [[ "${REPORT_JSON}" == *'"kind":"fault"'* ]]
  [[ "${REPORT_JSON}" == *'"reason":"exception"'* ]]
  [ "$status" -eq 1 ]
}

@test "hostile smc hvt" {
  skip_unless_host_is Darwin
  hostile_run smc
  [[ "${REPORT_JSON}" == *'"kind":"fault"'* ]]
  [[ "${REPORT_JSON}" == *'"reason":"exception"'* ]]
  [ "$status" -eq 1 ]
}

@test "hostile exec_bss hvt" {
  skip_unless_host_is Darwin
  hostile_run exec_bss
  [[ "${REPORT_JSON}" == *'"kind":"fault"'* ]]
  [[ "${REPORT_JSON}" == *'"reason":"translation_fault"'* ]]
  [ "$status" -eq 1 ]
}

@test "hostile exec_heap hvt" {
  skip_unless_host_is Darwin
  hostile_run exec_heap
  [[ "${REPORT_JSON}" == *'"kind":"fault"'* ]]
  [[ "${REPORT_JSON}" == *'"reason":"translation_fault"'* ]]
  [ "$status" -eq 1 ]
}

@test "hostile exec_stack hvt" {
  skip_unless_host_is Darwin
  hostile_run exec_stack
  [[ "${REPORT_JSON}" == *'"kind":"fault"'* ]]
  [[ "${REPORT_JSON}" == *'"reason":"translation_fault"'* ]]
  [ "$status" -eq 1 ]
}

@test "hostile exec_tls hvt" {
  skip_unless_host_is Darwin
  hostile_run exec_tls
  [[ "${REPORT_JSON}" == *'"kind":"fault"'* ]]
  [[ "${REPORT_JSON}" == *'"reason":"translation_fault"'* ]]
  [ "$status" -eq 1 ]
}

@test "user_memory hvt" {
  hvt_run --mem=64 -- test_user_memory/test_user_memory.hvt
  expect_success
}

@test "user_memory exec_heap hvt" {
  skip_unless_host_is Darwin
  REPORT=${BATS_TMPDIR}/exit-report.json
  run ${TIMEOUT} --foreground 60s "${HVT_TENDER}" --mem=64 --exit-report=3 \
    -- test_user_memory/test_user_memory.hvt exec_heap 3>${REPORT}
  REPORT_JSON=$(cat ${REPORT})
  echo "exit report: ${REPORT_JSON}"
  [[ "${REPORT_JSON}" == *'"reason":"translation_fault"'* ]]
  [ "$status" -eq 1 ]
}

@test "user_memory past guest memory hvt" {
  hvt_run --mem=16 -- test_user_memory/test_user_memory.hvt
  [ "$status" -eq 1 ] && \
    [[ "$output" == *"User memory 'fixed' [0x1000000, 0x1400000) ends past guest memory"* ]]
}

@test "user_memory no heap left hvt" {
  hvt_run --mem=28 -- test_user_memory/test_user_memory.hvt
  [ "$status" -eq 1 ] && \
    [[ "$output" == *"leaves less than 512 KB above 0x1c00000"* ]]
}

@test "user_memory over the image hvt" {
  hvt_run -- test_user_memory_overlap/test_user_memory_overlap.hvt
  [ "$status" -eq 1 ] && [[ "$output" == *"overlaps the unikernel's image"* ]]
}

@test "user_memory manifest elftool" {
  run sh user_memory_manifest.sh
  [ "$status" -eq 0 ] && [[ "$output" == *"PASS:"* ]]
}

@test "hostile hypercall_reserved hvt" {
  skip_unless_host_is Darwin
  hostile_run hypercall_reserved
  [[ "${REPORT_JSON}" == *'"kind":"fault"'* ]]
  [[ "${REPORT_JSON}" == *'"reason":"invalid_access"'* ]]
  [ "$status" -eq 1 ]
}

@test "hostile hypercall_unregistered hvt" {
  skip_unless_host_is Darwin
  hostile_run hypercall_unregistered
  [[ "${REPORT_JSON}" == *'"kind":"fault"'* ]]
  [[ "${REPORT_JSON}" == *'"reason":"invalid_access"'* ]]
  [ "$status" -eq 1 ]
}

@test "hostile hypercall_bad_gpa hvt" {
  skip_unless_host_is Darwin
  hostile_run hypercall_bad_gpa
  [[ "${REPORT_JSON}" == *'"kind":"fault"'* ]]
  [[ "${REPORT_JSON}" == *'"reason":"invalid_access"'* ]]
  [ "$status" -eq 1 ]
}

@test "hostile hypercall_wide_store hvt" {
  skip_unless_host_is Darwin
  hostile_run hypercall_wide_store
  [[ "${REPORT_JSON}" == *'"kind":"fault"'* ]]
  [[ "${REPORT_JSON}" == *'"reason":"invalid_access"'* ]]
  [ "$status" -eq 1 ]
}

@test "hostile hypercall_load hvt" {
  skip_unless_host_is Darwin
  hostile_run hypercall_load
  [[ "${REPORT_JSON}" == *'"kind":"fault"'* ]]
  [[ "${REPORT_JSON}" == *'"reason":"invalid_access"'* ]]
  [ "$status" -eq 1 ]
}

@test "hostile mmio_unassigned hvt" {
  skip_unless_host_is Darwin
  hostile_run mmio_unassigned
  [[ "${REPORT_JSON}" == *'"kind":"fault"'* ]]
  [[ "${REPORT_JSON}" == *'"reason":"invalid_access"'* ]]
  [ "$status" -eq 1 ]
}

@test "hostile console_overflow hvt" {
  skip_unless_host_is Darwin
  hostile_run console_overflow
  [[ "${REPORT_JSON}" == *'"kind":"fault"'* ]]
  [[ "${REPORT_JSON}" == *'"reason":"invalid_access"'* ]]
  [ "$status" -eq 1 ]
}

@test "hostile beyond_ram hvt" {
  skip_unless_host_is Darwin
  hostile_run beyond_ram
  [[ "${REPORT_JSON}" == *'"kind":"guest_abort"'* ]]
  [ "$status" -eq 255 ]
}

@test "hostile random_bad_gpa hvt" {
  skip_unless_host_is Darwin
  hostile_run random_bad_gpa
  [[ "${REPORT_JSON}" == *'"kind":"fault"'* ]]
  [[ "${REPORT_JSON}" == *'"reason":"invalid_access"'* ]]
  [ "$status" -eq 1 ]
}

@test "hostile random_wrap hvt" {
  skip_unless_host_is Darwin
  hostile_run random_wrap
  [[ "${REPORT_JSON}" == *'"kind":"fault"'* ]]
  [[ "${REPORT_JSON}" == *'"reason":"invalid_access"'* ]]
  [ "$status" -eq 1 ]
}

@test "hostile random_unoffered hvt" {
  skip_unless_host_is Darwin
  hostile_run random_unoffered
  [[ "${REPORT_JSON}" == *'"kind":"guest_exit"'* ]]
  expect_success
}

@test "hostile random_unoffered --no-random hvt" {
  skip_unless_host_is Darwin
  REPORT=${BATS_TMPDIR}/exit-report.json
  run ${TIMEOUT} --foreground 60s "${HVT_TENDER}" --mem=32 --no-random \
    --exit-report=3 -- test_hostile/test_hostile.hvt random_unoffered 3>${REPORT}
  REPORT_JSON=$(cat ${REPORT})
  echo "exit report: ${REPORT_JSON}"
  [[ "${REPORT_JSON}" == *'"kind":"fault"'* ]]
  [[ "${REPORT_JSON}" == *'"reason":"invalid_access"'* ]]
  [ "$status" -eq 1 ]
}

@test "hostile hypercall_wzr hvt" {
  skip_unless_host_is Darwin
  hostile_run hypercall_wzr
  [[ "${REPORT_JSON}" == *'"kind":"guest_exit"'* ]]
  expect_success
}

@test "hvf exit decoder hvt" {
  skip_unless_host_is Darwin
  run ${TIMEOUT} --foreground 120s fuzz_hvf_decode/check
  [ "$status" -eq 0 ] && [[ "$output" == *"SUCCESS"* ]]
}

@test "seccomp spt" {
  spt_run test_seccomp/test_seccomp.spt
  [ "$status" -eq 159 ] # SIGSYS
}

@test "blk hvt" {
  setup_block
  hvt_run --block:storage=${BLOCK} -- test_blk/test_blk.hvt
  expect_success
}

@test "blk block-sector-size=4096 hvt" {
  setup_block
  hvt_run --block:storage=${BLOCK} --block-sector-size:storage=4096 -- test_blk/test_blk.hvt
  expect_success
}

@test "blk misaligned hvt" {
  dd if=/dev/zero of=${BATS_TMPDIR}/storage.img \
      bs=2k count=3 status=none
  hvt_run --block:storage=${BATS_TMPDIR}/storage.img \
      --block-sector-size:storage=4096 -- test_blk/test_blk.hvt
  [ "$status" = 1 ] && [[ "$output" == *"Backing storage size must be block aligned"* ]]
}

@test "blk odd hvt" {
  dd if=/dev/zero of=${BATS_TMPDIR}/storage.img \
      bs=521 count=3 status=none
  hvt_run --block:storage=${BATS_TMPDIR}/storage.img \
      --block-sector-size:storage=521 -- test_blk/test_blk.hvt
  [ "$status" = 1 ] && [[ "$output" == *"Block size must be a multiple of 2"* ]]
}

@test "blk too small hvt" {
  dd if=/dev/zero of=${BATS_TMPDIR}/storage.img \
      bs=256 count=1 status=none
  hvt_run --block:storage=${BATS_TMPDIR}/storage.img \
      --block-sector-size:storage=256 -- test_blk/test_blk.hvt
  [ "$status" = 1 ] && [[ "$output" == *"Block size must be a multiple of 2 greater than or equal 512"* ]]
}

@test "blk virtio" {
  setup_block
  virtio_run -d ${BLOCK} -- test_blk/test_blk.virtio
  virtio_expect_success
}

@test "blk spt" {
  setup_block
  spt_run --block:storage=${BLOCK} -- test_blk/test_blk.spt
  expect_success
}

@test "blk block-sector-size=4096 spt" {
  setup_block
  spt_run --block:storage=${BLOCK} --block-sector-size:storage=4096 -- test_blk/test_blk.spt
  expect_success
}

@test "blk misaligned spt" {
  dd if=/dev/zero of=${BATS_TMPDIR}/storage.img \
      bs=2k count=3 status=none
  spt_run --block:storage=${BATS_TMPDIR}/storage.img \
      --block-sector-size:storage=4096 -- test_blk/test_blk.spt
  [ "$status" = 1 ] && [[ "$output" == *"Backing storage size must be block aligned"* ]]
}

@test "blk odd spt" {
  dd if=/dev/zero of=${BATS_TMPDIR}/storage.img \
      bs=521 count=3 status=none
  spt_run --block:storage=${BATS_TMPDIR}/storage.img \
      --block-sector-size:storage=521 -- test_blk/test_blk.spt
  [ "$status" = 1 ] && [[ "$output" == *"Block size must be a multiple of 2"* ]]
}

@test "blk too small spt" {
  dd if=/dev/zero of=${BATS_TMPDIR}/storage.img \
      bs=256 count=1 status=none
  spt_run --block:storage=${BATS_TMPDIR}/storage.img \
      --block-sector-size:storage=256 -- test_blk/test_blk.spt
  [ "$status" = 1 ] && [[ "$output" == *"Block size must be a multiple of 2 greater than or equal 512"* ]]
}

@test "net hvt" {
  if use_netpeer; then
    netpeer_hvt_run -n 1 -c 100000 -- \
      --net:service0=@3 -- test_net/test_net.hvt limit
  else
    skip_unless_root
    ( sleep 1; ${TIMEOUT} 60s ping -fq -c 100000 ${NET0_IP} ) &
    hvt_run --net:service0=${NET0} -- test_net/test_net.hvt limit
  fi
  expect_success
}

@test "net virtio" {
  skip_unless_root

  ( sleep 3; ${TIMEOUT} 60s ping -fq -c 100000 ${NET0_IP} ) &
  virtio_run -n ${NET0} -- test_net/test_net.virtio limit
  virtio_expect_success
}

@test "net spt" {
  skip_unless_root

  ( sleep 1; ${TIMEOUT} 60s ping -fq -c 100000 ${NET0_IP} ) &
  spt_run --net:service0=${NET0} -- test_net/test_net.spt limit
  expect_success
}

@test "net_2if hvt" {
  if use_netpeer; then
    netpeer_hvt_run -n 2 -- \
      --net:service0=@3 --net:service1=@4 -- test_net_2if/test_net_2if.hvt limit
  else
    skip_unless_root
    [ "${CONFIG_HOST}" = "OpenBSD" ] && skip "breaks on OpenBSD due to #374"

    ( sleep 1; ${TIMEOUT} 60s ping -fq -c 50000 ${NET0_IP} ) &
    ( sleep 1; ${TIMEOUT} 60s ping -fq -c 50000 ${NET1_IP} ) &
    hvt_run --net:service0=${NET0} --net:service1=${NET1} -- \
        test_net_2if/test_net_2if.hvt limit
  fi
  expect_success
}

@test "net_2if virtio" {
  [ $(id -u) -ne 0 ] && skip "Need root to run this test, for ping -f"
  [ "${CONFIG_HOST}" = "OpenBSD" ] && skip "breaks on OpenBSD due to #374"

  ( sleep 2; ${TIMEOUT} 60s ping -fq -c 50000 ${NET0_IP} ) &
  ( sleep 2; ${TIMEOUT} 60s ping -fq -c 50000 ${NET1_IP} ) &
  virtio_run -n ${NET0} -n ${NET1} -- \
      test_net_2if/test_net_2if.virtio limit
  virtio_expect_success
}

@test "net_2if spt" {
  skip_unless_root

  ( sleep 1; ${TIMEOUT} 60s ping -fq -c 50000 ${NET0_IP} ) &
  ( sleep 1; ${TIMEOUT} 60s ping -fq -c 50000 ${NET1_IP} ) &
  spt_run --net:service0=${NET0} --net:service1=${NET1} -- \
      test_net_2if/test_net_2if.spt limit
  expect_success
}

@test "net_mtu hvt" {
  if use_netpeer; then
    netpeer_hvt_run -n 1 -c 0 -- \
      --net:service0=@3 --net-mtu:service0=9000 -- test_net_mtu/test_net_mtu.hvt
  else
    skip_unless_root
    hvt_run --net:service0=${NET2} -- test_net_mtu/test_net_mtu.hvt
  fi
  [[ "$output" == *"MTU is 9000"* ]]
  expect_success
}

@test "net_mtu spt" {
  skip_unless_root
  spt_run --net:service0=${NET2} -- test_net_mtu/test_net_mtu.spt
  [[ "$output" == *"MTU is 9000"* ]]
  expect_success
}

@test "net_mtu virtio" {
  skip_unless_root
  virtio_run -n ${NET2}:9000 -- test_net_mtu/test_net_mtu.virtio
  [[ "$output" == *"MTU is 9000"* ]]
  virtio_expect_success
}

@test "net_ring hvt" {
  if use_netpeer; then
    netpeer_hvt_run -n 1 -p deadbeef -- \
      --net:service0=@3 -- test_net_ring/test_net_ring.hvt
  else
    skip_unless_root
    skip_unless_host_is Linux

    ( sleep 1; ${TIMEOUT} 60s ping -fq -c 10000 -p deadbeef ${NET0_IP} ) &
    hvt_run --net:service0=${NET0} -- test_net_ring/test_net_ring.hvt
  fi
  expect_success
}

@test "net_ring spt" {
  skip_unless_root

  ( sleep 1; ${TIMEOUT} 60s ping -fq -c 10000 -p deadbeef ${NET0_IP} ) &
  spt_run --net:service0=${NET0} -- test_net_ring/test_net_ring.spt
  expect_success
}

@test "net_ring memory hvt" {
  local mem=32
  local peer=() net=--net:service0=${NET2}
  if use_netpeer; then
    peer=(netpeer/netpeer -n 1 -c 0 --)
    net=--net:service0=@3
  else
    skip_unless_root
  fi

  run ${TIMEOUT} --foreground 60s "${peer[@]}" "${HVT_TENDER}" --mem=${mem} \
    ${net} -- test_net_mtu/test_net_mtu.hvt
  expect_success
  local with_ring=$(guest_mem_mb)

  run ${TIMEOUT} --foreground 60s "${peer[@]}" "${HVT_TENDER}" --mem=${mem} \
    --no-net-ring ${net} -- test_net_mtu/test_net_mtu.hvt
  expect_success
  local without_ring=$(guest_mem_mb)

  [ "${without_ring}" = "${mem}" ]
  [ -n "${with_ring}" ]
  [ "${with_ring}" -lt "${without_ring}" ]
  [ $(( with_ring % 2 )) -eq 0 ] # must be aligned
}

@test "dumpcore hvt" {
  [ "${CONFIG_HOST_ARCH}" = "x86_64" ] || skip "not implemented for ${CONFIG_HOST_ARCH}"
  skip_unless_host_is Linux FreeBSD

  run ${TIMEOUT} --foreground 60s ${HVT_TENDER_DEBUG} \
     --dumpcore="$BATS_TMPDIR" test_dumpcore/test_dumpcore.hvt
  [ "$status" -eq 255 ]
  CORE=`echo "$output" | grep -o "core\.solo5-hvt\.[0-9]*$"`
  [ -f "$BATS_TMPDIR"/"$CORE" ]
}

@test "mft_maxdevices hvt" {
  for num in $(${SEQ} 0 62); do
      dd if=/dev/zero of=${BATS_TMPDIR}/storage${num}.img \
          bs=4k count=1 status=none
  done

  DEVS=$(
  for num in $(${SEQ} 0 62); do
      echo -n "--block:storage${num}=${BATS_TMPDIR}/storage${num}.img "
  done
  )

  hvt_run ${DEVS} -- test_mft_maxdevices/test_mft_maxdevices.hvt
  expect_success
}

@test "mft_maxdevices spt" {
  for num in $(${SEQ} 0 62); do
      dd if=/dev/zero of=${BATS_TMPDIR}/storage${num}.img \
          bs=4k count=1 status=none
  done

  DEVS=$(
  for num in $(${SEQ} 0 62); do
      echo -n "--block:storage${num}=${BATS_TMPDIR}/storage${num}.img "
  done
  )

  spt_run ${DEVS} -- test_mft_maxdevices/test_mft_maxdevices.spt
  expect_success
}

@test "too_many_entries elftool" {
  elftool_manifest test_too_many_entries/manifest.json
  [ "$status" -eq 1 ] && \
    [[ "$output" == *"too many entries, maximum 63"* ]]
}

@test "buggyelf hvt" {
  # The fixture was fuzzed on x86_64. The aarch64 copy differs only in
  # e_machine, so that the tender gets past the header check to the note.
  case "${CONFIG_TARGET_ARCH}" in
  x86_64)  hvt_run test_buggyelf/buggyelf.hvt ;;
  aarch64) hvt_run test_buggyelf/buggyelf_aarch64.hvt ;;
  *)       skip "no buggy ELF fixture for ${CONFIG_TARGET_ARCH}" ;;
  esac
  [ "$status" -eq 1 ] && \
    [[ "$output" == *"note does not fall within valid size"* ]]
}

# Portable regressions exercise the same headers as the native tender.
@test "vmnet egress policy" {
  run make -C vmnet_policy check
  [ "$status" -eq 0 ] && [[ "$output" == *"PASS:"* ]]
}

@test "guest address bounds" {
  run sh hvt_gpa_bounds.sh
  [ "$status" -eq 0 ] && [[ "$output" == *"PASS:"* ]]
}

@test "sandbox descriptor gaps" {
  run sh hvt_sandbox_rlimit.sh
  [ "$status" -eq 0 ] && [[ "$output" == *"PASS:"* ]]
}

@test "debugger packet bounds" {
  run sh hvt_gdb_protocol.sh
  [ "$status" -eq 0 ] && [[ "$output" == *"PASS:"* ]]
}

@test "network manifest names" {
  run sh hvt_net_names.sh
  [ "$status" -eq 0 ] && [[ "$output" == *"PASS:"* ]]
}

@test "network backpressure" {
  run sh hvt_net_backpressure.sh
  [ "$status" -eq 0 ] && [[ "$output" == *"PASS:"* ]]
}

@test "pure BSS ELF segment bounds" {
  run sh elf_bss_bounds.sh
  [ "$status" -eq 0 ] && [[ "$output" == *"PASS:"* ]]
}

@test "Muen resource reader bounds" {
  run sh muen_reader_bounds.sh
  [ "$status" -eq 0 ] && [[ "$output" == *"PASS:"* ]]
}

@test "network ring bounds" {
  run sh hvt_ring_bounds.sh
  [ "$status" -eq 0 ] && [[ "$output" == *"PASS:"* ]]
}

@test "structured exit report classifications" {
  run sh hvt_exit_report.sh
  [ "$status" -eq 0 ] && [[ "$output" == *"PASS:"* ]]
}

@test "Linux watchdog seccomp syscalls" {
  skip_unless_host_is Linux
  run sh hvt_seccomp_watchdog.sh
  [ "$status" -eq 0 ] && [[ "$output" == *"PASS:"* ]]
}

@test "Linux sandboxed exit report classifications" {
  skip_unless_host_is Linux
  run env HVT_REPORT_SECCOMP=1 sh hvt_exit_report.sh
  [ "$status" -eq 0 ] && [[ "$output" == *"PASS:"* ]]
}

@test "Muen network resource name bounds" {
  run sh muen_net_names.sh
  [ "$status" -eq 0 ] && [[ "$output" == *"PASS:"* ]]
}
