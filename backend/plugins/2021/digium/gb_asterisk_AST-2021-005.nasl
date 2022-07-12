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

CPE = "cpe:/a:digium:asterisk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145420");
  script_version("2021-02-19T04:26:36+0000");
  script_tag(name:"last_modification", value:"2021-02-19 11:47:28 +0000 (Fri, 19 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-19 04:16:47 +0000 (Fri, 19 Feb 2021)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2021-26906");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk DoS Vulnerability (AST-2021-005)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_asterisk_detect.nasl");
  script_mandatory_keys("Asterisk-PBX/Installed");

  script_tag(name:"summary", value:"Asterisk is prone to a denial of service vulnerability in the PJSIP
  channel driver.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Given a scenario where an outgoing call is placed from Asterisk to a
  remote SIP server it is possible for a crash to occur.

  The code responsible for negotiating SDP in SIP responses incorrectly assumes that SDP negotiation will
  always be successful. If a SIP response containing an SDP that can not be negotiated is received a subsequent
  SDP negotiation on the same call can cause a crash.

  If the 'accept_multiple_sdp_answers' option in the 'system' section of pjsip.conf is set to 'yes' then any
  subsequent non-forked SIP response with SDP can trigger this crash.

  If the 'follow_early_media_fork' option in the 'system' section of pjsip.conf is set to 'yes' (the default)
  then any subsequent SIP responses with SDP from a forked destination can trigger this crash.

  If a 200 OK with SDP is received from a forked destination it can also trigger this crash, even if the
  'follow_early_media_fork' option is not set to 'yes'.

  In all cases this relies on a race condition with tight timing where the second SDP negotiation occurs
  before termination of the call due to the initial SDP negotiation failure.");

  script_tag(name:"affected", value:"Asterisk Open Source 13.x, 16.x, 17.x, 18.x and 16.x Certified Asterisk.");

  script_tag(name:"solution", value:"Update to version 13.38.2, 16.16.1, 17.9.2, 18.2.1, 16.8-cert6 or later.");

  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2021-005.html");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^13\.") {
  if (version_is_less(version: version, test_version: "13.38.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "13.38.2");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

if (version =~ "^16\.") {
  if (version =~ "^16\.[0-9]cert") {
    if (revcomp(a: version, b: "16.8cert6") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "16.8-cert6");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "16.16.1")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "16.16.1");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version_in_range(version: version, test_version: "17.0", test_version2: "17.9.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "17.9.2");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

if (version_in_range(version: version, test_version: "18.0", test_version2: "18.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.2.1");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

exit(99);
