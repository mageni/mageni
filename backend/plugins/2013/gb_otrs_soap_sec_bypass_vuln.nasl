###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_soap_sec_bypass_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# OTRS SOAP Security Bypass Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Updated by Thanga Prakash S <tprakash@secpod.com> on 2015-05-26
# Changed from exploit based to version check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803947");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2008-1515");
  script_bugtraq_id(74733);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-09-28 13:08:01 +0530 (Sat, 28 Sep 2013)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("OTRS SOAP Security Bypass Vulnerability");

  script_tag(name:"summary", value:"This host is installed with
  OTRS (Open Ticket Request System) and is prone to security bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error exists in SOAP interface which
  fails to properly validate user credentials before performing certain actions.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to read and modify objects via the OTRS SOAP interface.");

  script_tag(name:"affected", value:"OTRS (Open Ticket Request System)
  version 2.1.0 before 2.1.8 and 2.2.0 before 2.2.6");

  script_tag(name:"solution", value:"Upgrade to OTRS version 2.1.8 or 2.2.6
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");
  script_xref(name:"URL", value:"http://www.otrs.com/en");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");


if(!otrsport = get_app_port(cpe:CPE)){
  exit(0);
}

if(!otrsVer = get_app_version(cpe:CPE, port:otrsport)){
  exit(0);
}

if(otrsVer =~ "^2\.(1|2)")
{
  if(version_in_range(version:otrsVer, test_version:"2.1.0", test_version2:"2.1.7")||
     version_in_range(version:otrsVer, test_version:"2.2.0", test_version2:"2.2.5"))
  {
    security_message(port:otrsport);
    exit(0);
  }
}
