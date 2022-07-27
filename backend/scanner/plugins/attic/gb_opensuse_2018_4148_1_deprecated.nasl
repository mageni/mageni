# Copyright (C) 2018 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852193");
  script_version("2020-04-02T11:36:28+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_cve_id("CVE-2018-17204", "CVE-2018-17205", "CVE-2018-17206");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2018-12-18 07:42:02 +0100 (Tue, 18 Dec 2018)");
  script_name("openSUSE: Security Advisory for openvswitch (openSUSE-SU-2018:4148-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");

  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-12/msg00044.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openvswitch'
  package(s) announced via the openSUSE-SU-2018:4148-1 advisory.

  This NVT has been replaced by OID:1.3.6.1.4.1.25623.1.0.814571");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openvswitch to version 2.7.6 fixes the following issues:

  These security issues were fixed:

  - CVE-2018-17205: Prevent OVS crash when reverting old flows in bundle
  commit (bsc#1104467).

  - CVE-2018-17206: Avoid buffer overread in BUNDLE action decoding
  (bsc#1104467).

  - CVE-2018-17204:When decoding a group mod, it validated the group type
  and command after the whole group mod has been decoded. The OF1.5
  decoder, however, tried to use the type and command earlier, when it
  might still be invalid. This caused an assertion failure (via
  OVS_NOT_REACHED) (bsc#1104467).

  These non-security issues were fixed:

  - ofproto/bond: Fix bond reconfiguration race condition.

  - ofproto/bond: Fix bond post recirc rule leak.

  - ofproto/bond: fix internal flow leak of tcp-balance bond

  - systemd: Restart openvswitch service if a daemon crashes

  - conntrack: Fix checks for TCP, UDP, and IPv6 header sizes.

  - ofp-actions: Fix translation of set_field for nw_ecn

  - netdev-dpdk: Fix mempool segfault.

  - ofproto-dpif-upcall: Fix flow setup/delete race.

  - learn: Fix memory leak in learn_parse_sepc()

  - netdev-dpdk: fix mempool_configure error state

  - vswitchd: Add --cleanup option to the 'appctl exit' command

  - ofp-parse: Fix memory leak on error path in parse_ofp_group_mod_file().

  - actions: Fix memory leak on error path in parse_ct_lb_action().

  - dpif-netdev: Fix use-after-free error in reconfigure_datapath().

  - bridge: Fix memory leak in bridge_aa_update_trunks().

  - dpif-netlink: Fix multiple-free and fd leak on error path.

  - ofp-print: Avoid array overread in print_table_instruction_features().

  - flow: Fix buffer overread in flow_hash_symmetric_l3l4().

  - systemd: start vswitchd after udev

  - ofp-util: Check length of buckets in ofputil_pull_ofp15_group_mod().

  - ovsdb-types: Fix memory leak on error path.

  - tnl-ports: Fix loss of tunneling upon removal of a single tunnel port.

  - netdev: check for NULL fields in netdev_get_addrs

  - netdev-dpdk: vhost get stats fix.

  - netdev-dpdk: use 64-bit arithmetic when converting rates.

  - ofp-util: Fix buffer overread in ofputil_decode_bundle_add().

  - ofp-util: Fix memory leaks on error cases in ofputil_decode_group_mod().

  - ofp-util: Fix memory leaks when parsing OF1.5 group properties.

  - ofp-actions: Fix buffer overread in decode_LEARN_specs().

  - flow: Fix buffer overread for crafted IPv6 packets.

  - ofp-actions: Properly interpret 'output:in_port'.

  - ovs-ofctl: Avoid read overrun in ofperr_decode_msg().

  - odp-util: Avoid misaligned references to ip6_hdr.

  - ofproto-dpif-upc ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"openvswitch on openSUSE Leap 42.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in OID:1.3.6.1.4.1.25623.1.0.814571
