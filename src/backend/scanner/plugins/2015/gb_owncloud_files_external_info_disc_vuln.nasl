###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_files_external_info_disc_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# ownCloud 'files_external' RSA Key Validation Information Disclosure Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805283");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2014-5341");
  script_bugtraq_id(70039);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-02-19 17:25:47 +0530 (Thu, 19 Feb 2015)");
  script_name("ownCloud 'files_external' RSA Key Validation Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"The host is installed with ownCloud and
  is prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The error exists due to error in the SFTP
  external storage driver that is triggered as RSA Host Keys are verified after
  logging in.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct man-in-the-middle attack and spoof a valid host key
  bypassing authentication.");

  script_tag(name:"affected", value:"ownCloud Server 6.x before 6.0.5");

  script_tag(name:"solution", value:"Upgrade to ownCloud Server 6.0.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://owncloud.org/security/advisory/?id=oc-sa-2014-019");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_detect.nasl");
  script_mandatory_keys("owncloud/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://owncloud.org");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ownPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ownVer = get_app_version(cpe:CPE, port:ownPort)){
  exit(0);
}

if(ownVer =~ "^6")
{
  if(version_in_range(version:ownVer, test_version:"6.0.0", test_version2:"6.0.4"))
  {
    report = 'Installed version: ' + ownVer + '\n' +
           'Fixed version:     ' + "6.0.5" + '\n';

    security_message(port:ownPort, data:report);
    exit(0);
  }
}

exit(99);