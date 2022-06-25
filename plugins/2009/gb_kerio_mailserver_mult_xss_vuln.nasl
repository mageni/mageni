###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kerio_mailserver_mult_xss_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# Kerio Mail Server Multiple Cross Site Scripting vulnerabilities
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:kerio:kerio_mailserver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800099");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-01-08 07:43:30 +0100 (Thu, 08 Jan 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-5760", "CVE-2008-5769");
  script_bugtraq_id(32863);
  script_name("Kerio Mail Server Multiple Cross Site Scripting vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_kerio_mailserver_detect.nasl");
  script_mandatory_keys("KerioMailServer/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32955");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/47398");

  script_tag(name:"impact", value:"Successful exploitation could result in insertion of arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Kerio MailServer before 6.6.2 on all running platform.");

  script_tag(name:"insight", value:"Issues are due to,

  - a folder and daytime parameters in mailCompose.php and calendarEdit.php
  files is not properly sanitised before being returned to the user.

  - input passed to the sent parameter in error413.php is not properly
  sanitised before being returned to the user.");

  script_tag(name:"solution", value:"Upgrade to Kerio MailServer 6.6.2 or later.");

  script_tag(name:"summary", value:"The host is running Kerio Mail Server and is prone to multiple
  cross site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"6.6.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.6.2" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );