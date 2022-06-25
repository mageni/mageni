###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rsh_service_reporting.nasl 13010 2019-01-10 07:59:14Z cfischer $
#
# rsh Unencrypted Cleartext Login
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100080");
  script_version("$Revision: 13010 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-10 08:59:14 +0100 (Thu, 10 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-10-23 12:59:40 +0200 (Tue, 23 Oct 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  #Remark: NIST don't see "configuration issues" as software flaws so this CVSS has a value of 0.0.
  #However we still should report such a configuration issue with a criticality so this has been commented
  #out to avoid that the automatic CVSS score correction is setting the CVSS back to 0.0
  #  script_cve_id("CVE-1999-0651");
  script_name("rsh Unencrypted Cleartext Login");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Useless services");
  script_dependencies("rsh.nasl");
  script_mandatory_keys("rsh/detected");

  script_xref(name:"URL", value:"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0651");

  script_tag(name:"summary", value:"This remote host is running a rsh service.");

  script_tag(name:"insight", value:"rsh (remote shell) is a command line computer program which
  can execute shell commands as another user, and on another computer across a computer network.");

  script_tag(name:"solution", value:"Disable the rsh service and use alternatives like SSH instead.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

port = get_kb_item( "Services/rsh" );
if( ! port )
  port = 514;

if( ! get_kb_item( "rsh/" + port + "/detected" ) ) exit( 0 );
if( ! report = get_kb_item( "rsh/" + port + "/service_report" ) ) exit( 0 );

security_message( port:port, data:report );
exit( 0 );