###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms10_024.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Microsoft Windows SMTP Server MX Record Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:microsoft:exchange_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100596");
  script_version("$Revision: 13960 $");
  script_bugtraq_id(39308, 39381);
  script_cve_id("CVE-2010-0024", "CVE-2010-0025");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-04-22 20:18:17 +0200 (Thu, 22 Apr 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Microsoft Windows SMTP Server MX Record Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("SMTP problems");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("sw_ms_exchange_server_remote_detect.nasl");
  script_mandatory_keys("microsoft/exchange_server/smtp/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39308");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39381");
  script_xref(name:"URL", value:"http://www.microsoft.com");
  script_xref(name:"URL", value:"http://support.avaya.com/css/P8/documents/100079218");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/Bulletin/MS10-024.mspx");

  script_tag(name:"solution", value:"Microsoft released fixes to address this issue. Please see the
  references for more information.");

  script_tag(name:"summary", value:"The Microsoft Windows Simple Mail Transfer Protocol (SMTP) Server is
  prone to a denial-of-service vulnerability and to to an information-disclosure vulnerability.");

  script_tag(name:"impact", value:"Successful exploits of the denial-of-service vulnerability will cause the
  affected SMTP server to stop responding, denying service to legitimate users.

  Attackers can exploit the information-disclosure issue to gain access to
  sensitive information. Any information obtained may lead to further attacks.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smtp_func.inc");
include("version_func.inc");
include("host_details.inc");

function check_version(vers,range,fixed) {

  version = split(vers,  sep:".", keep:FALSE);
  fix     = split(fixed, sep:".", keep:FALSE);
  r       = split(range, sep:".", keep:FALSE);

  if(max_index(version) != 4) return FALSE;

  if(int(version[0]) == int(fix[0]) && int(version[1]) == int(fix[1]) && int(version[2]) == int(fix[2])) {

    if(int(version[3]) >= int(r[3])) {
      if(version_is_less(version:version[3], test_version:fix[3])) {
        return TRUE;
      }
    }
  }
  return FALSE;
}

if(!port = get_app_port(cpe:CPE, service:"smtp"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port))
  exit(0);

banner = get_smtp_banner(port:port);
if(!banner || "Microsoft ESMTP MAIL" >!< banner)
  exit(0);

version = eregmatch(pattern:"Version: ([0-9.]+)", string:banner);
if(!version[1])
  exit(0);

vers = version[1];

if(check_version(vers:vers, fixed:"6.0.2600.5949", range:"6.0.2600.5000")   || # xp sp3
   check_version(vers:vers, fixed:"5.0.2195.7381", range:"5.0.2195.0")      || # win 2000
   check_version(vers:vers, fixed:"6.0.3790.4675", range:"6.0.3790.0")      || # xp professional x64, win 2003
   check_version(vers:vers, fixed:"6.0.2600.3680", range:"6.0.2600.0")      || # xp sp2
   check_version(vers:vers, fixed:"7.5.7600.16544", range:"7.5.7600.16000") || # Server 2008 R2 x86/x64/ia64
   check_version(vers:vers, fixed:"7.5.7600.20660", range:"7.5.7600.20000")) { # Server 2008 R2 x86/x64/ia64
  report = report_fixed_ver(installed_version:vers, fixed_version:"See references");
  security_message(port:port, data:report);
  exit(0);
}

# extra check for some windows 2008 versions
else if((vers =~ "^[6-7]\.0\.6001\." && version_in_range(version:vers, test_version:"6.0.6001.22000", test_version2:"7.0.6001.22647")) || # Server 2008 32bit/x64
        (vers =~ "^[6-7]\.0\.6002\." && version_in_range(version:vers, test_version:"6.0.6002.18000", test_version2:"7.0.6002.18221"))) { # Server 2008 SP2 32bit/x64
  report = report_fixed_ver(installed_version:vers, fixed_version:"See references");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);