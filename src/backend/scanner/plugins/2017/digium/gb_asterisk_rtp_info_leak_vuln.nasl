###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asterisk_rtp_info_leak_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Asterisk RTP/RTCP Information Leak Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:digium:asterisk';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140380");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-20 14:43:21 +0700 (Wed, 20 Sep 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2017-14099", "CVE-2017-14603");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk RTP/RTCP Information Leak Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_asterisk_detect.nasl");
  script_mandatory_keys("Asterisk-PBX/Installed");

  script_tag(name:"summary", value:"Asterisk is prone to an information leak in RTP/RTCP.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Insufficient RTCP packet validation could allow reading stale buffer
contents and when combined with the 'nat' and 'symmetric_rtp' options allow redirecting where Asterisk sends the
next RTCP report.

The RTP stream qualification to learn the source address of media always accepted the first RTP packet as the
new source and allowed what AST-2017-005 was mitigating. The intent was to qualify a series of packets before
accepting the new source address.");

  script_tag(name:"impact", value:"An unauthenticated remote attacker may hijack the media stream.");

  script_tag(name:"affected", value:"Asterisk Open Source 11.x, 13.x, 14.x and Certified Asterisk 11.6 and
13.13.");

  script_tag(name:"solution", value:"Upgrade to Version 11.25.3, 13.17.2, 14.6.2, 11.6-cert18, 13.13-cert6 or
later.");

  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2017-008.html");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^11\.") {
  if (version =~ "^11\.6cert") {
    if (revcomp(a: version, b: "11.6cert18") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "11.6-cert18");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "11.25.3")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "11.25.3");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version =~ "^13\.") {
  if (version =~ "^13\.13cert") {
    if (revcomp(a: version, b: "13.13cert6") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.13-cert6");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "13.17.2")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.17.2");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version =~ "^14\.") {
  if (version_is_less(version: version, test_version: "14.6.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.6.2");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

exit(0);
