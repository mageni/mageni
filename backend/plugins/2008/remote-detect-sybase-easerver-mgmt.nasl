# OpenVAS Vulnerability Test
# $Id: remote-detect-sybase-easerver-mgmt.nasl 14240 2019-03-17 15:50:45Z cfischer $
# Description: This script ensure that the Sybase EAServer management console is running
#
# remote-detect-sybase-easerver-mgmt.nasl
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and later,
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80005");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-09-09 16:54:39 +0200 (Tue, 09 Sep 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Sybase Enterprise Application Server Management Console detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"general_note");

  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "remote-detect-sybase-easerver.nasl");
  script_require_ports("Services/www");
  script_mandatory_keys("SybaseEAServer/installed");

  script_tag(name:"solution", value:"It's recommended to allow connection to this host only from trusted host or networks,
  or disable the service if not used.");

  script_tag(name:"summary", value:"The remote host is running the Sybase Enterprise Application Server JSP Administration Console.
  Sybase EAServer is the open application server from Sybase Inc an enterprise software and services company,
  exclusively focused on managing and mobilizing information.

  This NVT was deprecated and the detection of the Server Management Console was moved to remote-detect-sybase-easerver.nasl");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);