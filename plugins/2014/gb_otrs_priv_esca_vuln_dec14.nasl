###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_priv_esca_vuln_dec14.nasl 11974 2018-10-19 06:22:46Z cfischer $
#
# OTRS Help Desk Privilege Escalation Vulnerability - Dec14
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805230");
  script_version("$Revision: 11974 $");
  script_cve_id("CVE-2014-9324");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:22:46 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-12-24 12:30:49 +0530 (Wed, 24 Dec 2014)");
  script_name("OTRS Help Desk Privilege Escalation Vulnerability - Dec14");

  script_tag(name:"summary", value:"This host is installed with OTRS (Open
  Ticket Request System) Help Desk and is prone to privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The error exists due to error in the
  'GenericInterface' that is due to a lack of sufficient permission checks.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to and make changes to ticket data of other users.");

  script_tag(name:"affected", value:"OTRS Help Desk versions 3.2.x before
  3.2.17, 3.3.x before 3.3.11, and 4.0.x before 4.0.3");

  script_tag(name:"solution", value:"Upgrade to OTRS Help Desk version 3.2.17
  or 3.3.11 or 4.0.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59875");
  script_xref(name:"URL", value:"https://www.otrs.com/security-advisory-2014-06-incomplete-access-control");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");
  script_xref(name:"URL", value:"http://www.otrs.com");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");


if(!otrsport = get_app_port(cpe:CPE)){
  exit(0);
}

if(!vers = get_app_version(cpe:CPE, port:otrsport)){
  exit(0);
}

if(vers =~ "^(3|4)")
{
  ## before 4.0.3
  if(version_in_range(version:vers, test_version:"3.2.0", test_version2:"3.2.16")||
     version_in_range(version:vers, test_version:"3.3.0", test_version2:"3.3.10")||
     version_in_range(version:vers, test_version:"4.0.0", test_version2:"4.0.2"))
  {
    security_message(port:otrsport);
    exit(0);
  }
}
