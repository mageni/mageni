###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_dos_vuln03_september14_win.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Wireshark Denial of Service Vulnerability-03 Sep14 (Windows)
#
# Authors:
# Deepmala <kdeepmala@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804915");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-6421", "CVE-2014-6422");
  script_bugtraq_id(69855, 69856);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-09-24 15:54:48 +0530 (Wed, 24 Sep 2014)");

  script_name("Wireshark Denial of Service Vulnerability-03 Sep14 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Wireshark
  and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws exists due to,

  - the SDP dissector creates duplicate hashtables for a media channel.

  - the Use-after-free vulnerability in the SDP dissector.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attacker to cause denial of service attack

  - via a crafted packet to the RTP dissector.

  - via a crafted packet that leverages split memory ownership between
  the SDP and RTP dissectors.");

  script_tag(name:"affected", value:"Wireshark version 1.10.x before 1.10.10 on Windows");

  script_tag(name:"solution", value:"Upgrade to Wireshark 1.10.10 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=9920");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2014-12.html");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!version = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:version, test_version:"1.10.0", test_version2:"1.10.9"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
