###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sendmail_bof_vuln.nasl 13074 2019-01-15 09:12:34Z cfischer $
#
# Sendmail Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:sendmail:sendmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800609");
  script_version("$Revision: 13074 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-15 10:12:34 +0100 (Tue, 15 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-05-13 10:01:19 +0200 (Wed, 13 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1490");
  script_name("Sendmail Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_sendmail_detect.nasl");
  script_mandatory_keys("sendmail/detected");

  script_xref(name:"URL", value:"http://www.sendmail.org/releases/8.13.2");
  script_xref(name:"URL", value:"http://www.nmrc.org/~thegnome/blog/apr09");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attacker to create the mangled
  message by execute arbitrary code, and can cause application crash.");

  script_tag(name:"affected", value:"Sendmail Version prior to 8.13.2.");

  script_tag(name:"insight", value:"Buffer overflow error is due to improper handling of long X- header.");

  script_tag(name:"solution", value:"Upgrade to version 8.13.2 or later.");

  script_tag(name:"summary", value:"The host is running Sendmail and is prone to Buffer Overflow Vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:vers, test_version:"8.13.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"8.13.2");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);