# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.853813");
  script_version("2021-05-26T07:20:58+0000");
  script_cve_id("CVE-2021-32917", "CVE-2021-32918", "CVE-2021-32919", "CVE-2021-32920");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2021-05-26 10:26:09 +0000 (Wed, 26 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-15 03:03:05 +0000 (Sat, 15 May 2021)");
  script_name("openSUSE: Security Advisory for prosody (openSUSE-SU-2021:0728-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0728-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QFZF2R5S5FEXEQIW4Q7P3QW6HA46PJMX");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'prosody'
  package(s) announced via the openSUSE-SU-2021:0728-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for prosody fixes the following issues:

     prosody was updated to 0.11.9:

     Security:

  * mod_limits, prosody.cfg.lua: Enable rate limits by default

  * certmanager: Disable renegotiation by default

  * mod_proxy65: Restrict access to local c2s connections by default

  * util.startup: Set more aggressive defaults for GC

  * mod_c2s, mod_s2s, mod_component, mod_bosh, mod_websockets: Set default
       stanza size limits

  * mod_authinternal{plain, hashed}: Use constant-time string comparison for
       secrets

  * mod_dialback: Remove dialback-without-dialback feature

  * mod_dialback: Use constant-time comparison with hmac

     Minor changes:

  * util.hashes: Add constant-time string comparison (binding to
       CRYPTO_memcmp)

  * mod_c2s: Dont throw errors in async code when connections are gone

  * mod_c2s: Fix traceback in session close when conn is nil

  * core.certmanager: Improve detection of LuaSec/OpenSSL capabilities

  * mod_saslauth: Use a defined SASL error

  * MUC: Add support for advertising muc#roomconfig_allowinvites in room
       disco#info

  * mod_saslauth: Dont throw errors in async code when connections are
       gone

  * mod_pep: Advertise base pubsub feature (fixes #1632: mod_pep missing
       pubsub feature in disco)

  * prosodyctl check config: Add gc to list of global options

  * prosodyctl about: Report libexpat version if known

  * util.xmppstream: Add API to dynamically configure the stanza size limit
       for a stream

  * util.set: Add is_set() to test if an object is a set

  * mod_http: Skip IP resolution in non-proxied case

  * mod_c2s: Log about missing conn on async state changes

  * util.xmppstream: Reduce internal default xmppstream limit to 1MB

  * boo#1186027: Prosody XMPP server advisory 2021-05-12

  * CVE-2021-32919

  * CVE-2021-32917

  * CVE-2021-32917

  * CVE-2021-32920

  * CVE-2021-32918

     Update to 0.11.8:

     Security:

  * mod_saslauth: Disable tls-unique channel binding with TLS 1.3
       (#1542)

     Fixes and improvements:

  * net.websocket.frames: Improve websocket masking performance by using the
       new util.strbitop

  * util.strbitop: Library for efficient bitwise operations on strings

     Minor changes:

  * MUC: Correctly advertise whether the subject can be changed (#1155)

  * MUC: Preserve disco node ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'prosody' package(s) on openSUSE Leap 15.2.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"prosody", rpm:"prosody~0.11.9~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prosody-debuginfo", rpm:"prosody-debuginfo~0.11.9~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"prosody-debugsource", rpm:"prosody-debugsource~0.11.9~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
