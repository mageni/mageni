###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms04_035.nasl 13135 2019-01-18 06:38:46Z cfischer $
#
# Microsoft SMTP Service and Exchange Routing Engine Buffer Overflow Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.100607");
  script_version("$Revision: 13135 $");
  script_bugtraq_id(11374);
  script_cve_id("CVE-2004-0840");
  script_name("Microsoft SMTP Service and Exchange Routing Engine Buffer Overflow Vulnerability");
  script_tag(name:"last_modification", value:"$Date: 2019-01-18 07:38:46 +0100 (Fri, 18 Jan 2019) $");
  script_tag(name:"creation_date", value:"2010-04-26 19:54:51 +0200 (Mon, 26 Apr 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("SMTP problems");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("sw_ms_exchange_server_remote_detect.nasl");
  script_mandatory_keys("microsoft/exchange_server/smtp/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11374");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/870540");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms04-035.mspx");

  script_tag(name:"summary", value:"The Microsoft Windows 2003 SMTP Service and Exchange Routing Engine
  have been reported prone to a buffer overflow. This occurs during the processing responses to DNS lookups.");

  script_tag(name:"impact", value:"Successful exploitation could allow for remote code execution in the context of the
  vulnerable service.");

  script_tag(name:"solution", value:"Microsoft has released a bulletin that includes fixes to address this
  issue for supported versions of the operating system.

  Note that the fix for Exchange Server 2000 Service Pack 3 requires that the Exchange 2000 Server Post-Service Pack 3 (SP3)
  Update Rollup be installed as a prerequisite. See Knowledge Base article 870540 in the References section for further
  details on this rollup.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smtp_func.inc");
include("version_func.inc");
include("host_details.inc");

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

vers = split(version[1], sep:".", keep:FALSE);

if(int(vers[0]) == 6 && int(vers[1]) == 0 && int(vers[2]) > 2600) {
  if((int(vers[2]) == 3790 && int(vers[3]) < 211 ) || int(vers[2]) < 3790) {
    report = report_fixed_ver(installed_version:version[1], fixed_version:"See references");
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);