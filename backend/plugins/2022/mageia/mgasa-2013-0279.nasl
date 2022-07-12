# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0279");
  script_cve_id("CVE-2013-2238");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2013-10-11 14:52:00 +0000 (Fri, 11 Oct 2013)");

  script_name("Mageia: Security Advisory (MGASA-2013-0279)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0279");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0279.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10743");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2013/07/01/11");
  script_xref(name:"URL", value:"http://jira.freeswitch.org/browse/FS-5566");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freeswitch' package(s) announced via the MGASA-2013-0279 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In FreeSWITCH before 1.2.12, if the routing configuration includes
regular expressions that don't constrain the length of the input, buffer
overflows are possible. Since these regular expressions are matched
against untrusted input, remote code execution may be possible
(CVE-2013-2238).");

  script_tag(name:"affected", value:"'freeswitch' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"dkms-skypopen", rpm:"dkms-skypopen~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch", rpm:"freeswitch~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-abstraction", rpm:"freeswitch-application-abstraction~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-avmd", rpm:"freeswitch-application-avmd~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-blacklist", rpm:"freeswitch-application-blacklist~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-callcenter", rpm:"freeswitch-application-callcenter~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-cidlookup", rpm:"freeswitch-application-cidlookup~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-conference", rpm:"freeswitch-application-conference~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-curl", rpm:"freeswitch-application-curl~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-db", rpm:"freeswitch-application-db~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-directory", rpm:"freeswitch-application-directory~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-distributor", rpm:"freeswitch-application-distributor~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-easyroute", rpm:"freeswitch-application-easyroute~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-enum", rpm:"freeswitch-application-enum~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-esf", rpm:"freeswitch-application-esf~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-expr", rpm:"freeswitch-application-expr~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-fifo", rpm:"freeswitch-application-fifo~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-fsk", rpm:"freeswitch-application-fsk~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-fsv", rpm:"freeswitch-application-fsv~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-ha_cluster", rpm:"freeswitch-application-ha_cluster~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-hash", rpm:"freeswitch-application-hash~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-httapi", rpm:"freeswitch-application-httapi~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-http-cache", rpm:"freeswitch-application-http-cache~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-lcr", rpm:"freeswitch-application-lcr~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-limit", rpm:"freeswitch-application-limit~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-memcache", rpm:"freeswitch-application-memcache~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-nibblebill", rpm:"freeswitch-application-nibblebill~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-redis", rpm:"freeswitch-application-redis~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-rss", rpm:"freeswitch-application-rss~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-sms", rpm:"freeswitch-application-sms~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-snapshot", rpm:"freeswitch-application-snapshot~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-snom", rpm:"freeswitch-application-snom~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-soundtouch", rpm:"freeswitch-application-soundtouch~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-spy", rpm:"freeswitch-application-spy~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-stress", rpm:"freeswitch-application-stress~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-valet_parking", rpm:"freeswitch-application-valet_parking~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-voicemail", rpm:"freeswitch-application-voicemail~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-application-voicemail-ivr", rpm:"freeswitch-application-voicemail-ivr~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-asrtts-flite", rpm:"freeswitch-asrtts-flite~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-asrtts-pocketsphinx", rpm:"freeswitch-asrtts-pocketsphinx~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-asrtts-tts-commandline", rpm:"freeswitch-asrtts-tts-commandline~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-asrtts-unimrcp", rpm:"freeswitch-asrtts-unimrcp~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-codec-bv", rpm:"freeswitch-codec-bv~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-codec-celt", rpm:"freeswitch-codec-celt~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-codec-codec2", rpm:"freeswitch-codec-codec2~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-codec-h26x", rpm:"freeswitch-codec-h26x~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-codec-ilbc", rpm:"freeswitch-codec-ilbc~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-codec-isac", rpm:"freeswitch-codec-isac~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-codec-mp4v", rpm:"freeswitch-codec-mp4v~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-codec-opus", rpm:"freeswitch-codec-opus~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-codec-passthru-amr", rpm:"freeswitch-codec-passthru-amr~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-codec-passthru-amrwb", rpm:"freeswitch-codec-passthru-amrwb~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-codec-passthru-g723_1", rpm:"freeswitch-codec-passthru-g723_1~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-codec-passthru-g729", rpm:"freeswitch-codec-passthru-g729~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-codec-silk", rpm:"freeswitch-codec-silk~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-codec-speex", rpm:"freeswitch-codec-speex~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-codec-theora", rpm:"freeswitch-codec-theora~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-config-vanilla", rpm:"freeswitch-config-vanilla~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-directory-ldap", rpm:"freeswitch-directory-ldap~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-endpoint-dingaling", rpm:"freeswitch-endpoint-dingaling~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-endpoint-portaudio", rpm:"freeswitch-endpoint-portaudio~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-endpoint-rtmp", rpm:"freeswitch-endpoint-rtmp~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-endpoint-skinny", rpm:"freeswitch-endpoint-skinny~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-endpoint-skypopen", rpm:"freeswitch-endpoint-skypopen~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-event-cdr-mongodb", rpm:"freeswitch-event-cdr-mongodb~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-event-cdr-pg-csv", rpm:"freeswitch-event-cdr-pg-csv~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-event-cdr-sqlite", rpm:"freeswitch-event-cdr-sqlite~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-event-erlang-event", rpm:"freeswitch-event-erlang-event~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-event-json-cdr", rpm:"freeswitch-event-json-cdr~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-event-multicast", rpm:"freeswitch-event-multicast~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-event-snmp", rpm:"freeswitch-event-snmp~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-format-local-stream", rpm:"freeswitch-format-local-stream~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-format-mod-shout", rpm:"freeswitch-format-mod-shout~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-format-native-file", rpm:"freeswitch-format-native-file~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-format-portaudio-stream", rpm:"freeswitch-format-portaudio-stream~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-format-shell-stream", rpm:"freeswitch-format-shell-stream~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-format-tone-stream", rpm:"freeswitch-format-tone-stream~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-freetdm", rpm:"freeswitch-freetdm~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-lang-de", rpm:"freeswitch-lang-de~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-lang-en", rpm:"freeswitch-lang-en~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-lang-es", rpm:"freeswitch-lang-es~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-lang-fr", rpm:"freeswitch-lang-fr~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-lang-he", rpm:"freeswitch-lang-he~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-lang-pt", rpm:"freeswitch-lang-pt~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-lang-ru", rpm:"freeswitch-lang-ru~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-lua", rpm:"freeswitch-lua~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-perl", rpm:"freeswitch-perl~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-python", rpm:"freeswitch-python~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-sounds-en", rpm:"freeswitch-sounds-en~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-sounds-es", rpm:"freeswitch-sounds-es~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-sounds-fr", rpm:"freeswitch-sounds-fr~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-sounds-moh", rpm:"freeswitch-sounds-moh~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-sounds-ru", rpm:"freeswitch-sounds-ru~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-sounds-sv", rpm:"freeswitch-sounds-sv~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-timer-posix", rpm:"freeswitch-timer-posix~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-xml-cdr", rpm:"freeswitch-xml-cdr~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeswitch-xml-curl", rpm:"freeswitch-xml-curl~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freeswitch-devel", rpm:"lib64freeswitch-devel~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freeswitch1", rpm:"lib64freeswitch1~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreeswitch-devel", rpm:"libfreeswitch-devel~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreeswitch1", rpm:"libfreeswitch1~1.2.12~6.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nagios-check_freeswitch", rpm:"nagios-check_freeswitch~1.2.12~6.mga3", rls:"MAGEIA3"))) {
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
