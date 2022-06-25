###############################################################################
# OpenVAS Vulnerability Test
# $Id: FtpXQ_36391.nasl 13613 2019-02-12 16:12:57Z cfischer $
#
# DataWizard FtpXQ Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100293");
  script_version("$Revision: 13613 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 17:12:57 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-10-06 18:45:43 +0200 (Tue, 06 Oct 2009)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3545");
  script_bugtraq_id(36391);
  script_name("DataWizard FtpXQ Remote Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/ftpxq/detected");

  script_tag(name:"summary", value:"FtpXQ is prone to a remote denial-of-service vulnerability.");

  script_tag(name:"impact", value:"Remote attackers can cause the affected server to stop responding,
  denying service to legitimate users.");

  script_tag(name:"affected", value:"FtpXQ 3.0 is vulnerable. Other versions may also be affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36391");
  script_xref(name:"URL", value:"http://www.datawizard.net");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("ftp_func.inc");
include("version_func.inc");

port = get_ftp_port(default:21);

if(!banner = get_ftp_banner(port:port))exit(0);
if("FtpXQ" >!< banner)exit(0);

version = eregmatch(string: banner, pattern:"Version ([0-9.]+)");

if(!isnull(version[1])) {
  if(version_is_equal(version: version[1], test_version: "3.0")) {
    security_message(port:port);
  }
}

exit(0);