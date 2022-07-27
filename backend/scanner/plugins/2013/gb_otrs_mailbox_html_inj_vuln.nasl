###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_mailbox_html_inj_vuln.nasl 11883 2018-10-12 13:31:09Z cfischer $
#
# OTRS Mailbox HTML Injection Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803945");
  script_version("$Revision: 11883 $");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:31:09 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-09-27 16:50:31 +0530 (Fri, 27 Sep 2013)");
  script_name("OTRS Mailbox HTML Injection Vulnerability");


  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject script code
into the OTRS webinterface.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"An error exists in application's agent mailbox view which fails to properly
sanitize user-supplied input before using it");
  script_tag(name:"solution", value:"Upgrade to OTRS (Open Ticket Request System) version 2.0.5 or later, or apply the patch
  from the referenced vendor advisory.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with OTRS (Open Ticket Request System) and is prone to
HTML injection vulnerability.");
  script_tag(name:"affected", value:"OTRS (Open Ticket Request System) version 2.0.0 up to and including 2.0.4.");

  script_xref(name:"URL", value:"http://otrs.org/advisory/OSA-2007-01-en/");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("secpod_otrs_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("OTRS/installed");
  script_xref(name:"URL", value:"http://www.otrs.com/en/");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");


if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(vers = get_app_version(cpe:CPE, port:port))
{
  if(version_in_range(version:vers, test_version:"2.0.0", test_version2:"2.0.4"))
  {
      security_message(port:port);
      exit(0);
  }

}
