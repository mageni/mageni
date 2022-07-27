###############################################################################
# OpenVAS Vulnerability Test
# $Id: policy_BSI-TR-03116-4_ok.nasl 10530 2018-07-17 14:15:42Z asteins $
#
# List positive results from Policy for BSI-TR-03116-4 Test
#
# Authors:
# Thomas Rotter <Thomas.Rotter@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96178");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10530 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-17 16:15:42 +0200 (Tue, 17 Jul 2018) $");
  script_tag(name:"creation_date", value:"2016-03-07 09:15:18 +0100 (Mon, 07 Mar 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("BSI-TR-03116-4: Matches");
  script_category(ACT_GATHER_INFO);
  script_family("Policy");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("Policy/policy_BSI-TR-03116-4.nasl");
  script_mandatory_keys("policy/BSI-TR-03116-4/ok", "ssl_tls/port");

  script_tag(name:"summary", value:"List positive results from Policy for BSI-TR-03116-4 Test");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("ssl_funcs.inc");

sslPort = get_ssl_port();
if( ! sslPort ) exit( 0 );

result = get_kb_item( "policy/BSI-TR-03116-4/" + sslPort + "/ok" );

if( result ) {
  report = "Mindestens einer der unter Punkt 2.1.2 geforderten Ciphers wurde auf Port " + sslPort + " gefunden:\n" + result;
  log_message( data:report, port:sslPort );
}

exit( 0 );
