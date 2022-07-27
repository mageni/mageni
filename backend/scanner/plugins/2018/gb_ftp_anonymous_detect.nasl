###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ftp_anonymous_detect.nasl 12030 2018-10-23 09:41:40Z cfischer $
#
# Anonymous FTP Login Reporting
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
  script_oid("1.3.6.1.4.1.25623.1.0.900600");
  script_version("$Revision: 12030 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-23 11:41:40 +0200 (Tue, 23 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-10-23 08:55:22 +0200 (Tue, 23 Oct 2018)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  #Remark: NIST don't see "configuration issues" as software flaws so this CVSS has a value of 0.0.
  #However we still should report such a configuration issue with a criticality so this has been commented
  #out to avoid that the automatic CVSS score correction is setting the CVSS back to 0.0
  #  script_cve_id("CVE-1999-0497");
  script_name("Anonymous FTP Login Reporting");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("secpod_ftp_anonymous.nasl");
  script_mandatory_keys("ftp/anonymous_ftp/detected");

  script_xref(name:"URL", value:"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0497");

  script_tag(name:"solution", value:"If you do not want to share files, you should disable anonymous logins.");

  script_tag(name:"insight", value:"A host that provides an FTP service may additionally provide Anonymous FTP
  access as well. Under this arrangement, users do not strictly need an account on the host. Instead the user
  typically enters 'anonymous' or 'ftp' when prompted for username. Although users are commonly asked to send
  their email address as their password, little to no verification is actually performed on the supplied data.");

  script_tag(name:"impact", value:"Based on the files accessible via this anonymous FTP login and the permissions
  of this account an attacker might be able to:

  - gain access to sensitive files

  - upload or delete files.");

  script_tag(name:"summary", value:"Reports if the remote FTP Server allows anonymous logins.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");

port = get_ftp_port( default:21 );

if( ! get_kb_item( "ftp/" + port + "/anonymous" ) ) exit( 0 );
if( ! report = get_kb_item( "ftp/" + port + "/anonymous_report" ) ) exit( 0 );

security_message( port:port, data:report );
exit( 0 );