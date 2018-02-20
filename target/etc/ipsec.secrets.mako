# /etc/ipsec.secrets - strongSwan IPsec secrets file

% if server_key_type == "rsa":
: RSA ${server_key_path}
% elif server_key_type == "ec":
: ECDSA ${server_key_path}
% else:
<%
    raise RuntimeError("unknown key type ({0}).".format(server_key_type))
%>
% endif
