###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_spoofing_vuln_jan16_macosx.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# Mozilla Firefox Spoofing Vulnerability - Jan16 (Mac OS X)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806953");
  script_version("$Revision: 12051 $");
  script_cve_id("CVE-2015-7575");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-01-14 10:52:36 +0530 (Thu, 14 Jan 2016)");
  script_name("Mozilla Firefox Spoofing Vulnerability - Jan16 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Firefox and is prone to spoofing vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to
  Network Security Services (NSS) does not reject MD5 signatures in Server Key
  Exchange messages in TLS 1.2 Handshake Protocol traffic.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  man-in-the-middle attackers to spoof servers by triggering a collision.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 43.0.2 on
  Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 43.0.2
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-150/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_is_less(version:ffVer, test_version:"43.0.2"))
{
  report = 'Installed version: ' + ffVer + '\n' +
           'Fixed version:     ' + "43.0.2" + '\n';
  security_message(data:report);
  exit(0);
}
