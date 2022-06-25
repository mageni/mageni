# OpenVAS Vulnerability Test
# $Id: SHN_Sendmail_DoublePipe.nasl 13074 2019-01-15 09:12:34Z cfischer $
# Description: Sendmail 8.8.8 to 8.12.7 Double Pipe Access Validation Vulnerability
#
# Authors:
# Vincent Renardias <vincent@strongholdnet.com>
#
# Copyright:
# Copyright (C) 2003 StrongHoldNet
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

CPE = "cpe:/a:sendmail:sendmail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11321");
  script_version("$Revision: 13074 $");
  script_bugtraq_id(5845);
  script_cve_id("CVE-2002-1165", "CVE-2002-1337");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-01-15 10:12:34 +0100 (Tue, 15 Jan 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("Sendmail 8.8.8 to 8.12.7 Double Pipe Access Validation Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 StrongHoldNet");
  script_family("SMTP problems");
  script_dependencies("gb_sendmail_detect.nasl");
  script_mandatory_keys("sendmail/detected");

  script_tag(name:"solution", value:"Upgrade to the latest version of Sendmail (or at least 8.12.8).");

  script_tag(name:"summary", value:"smrsh (supplied by Sendmail) is designed to prevent the execution of
  commands outside of the restricted environment. However, when commands are entered using either double
  pipes or a mixture of dot and slash characters, a user may be able to bypass the checks performed by
  smrsh. This can lead to the execution of commands outside of the restricted environment.");

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

if(vers =~ "^(8\.8\.[89]|8\.9\..*|8\.1[01]\.*|8\.12\.[0-7][^0-9])$") {
  report = report_fixed_ver(installed_version:vers, fixed_version:"8.12.8");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);