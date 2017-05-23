#!/usr/bin/python
#-*- coding:utf-8 -*-

from urllib import quote


def normalize_key(consumer_secret, oauth_token_secret=None):
    """
    Signature生成のためのKey情報を生成する。
    Args:
    consumer_secret: consumer_secret文字列
    oauth_token_secret: (オプション) oauth_token_secret情報
    Returns:
    oauth1.0のsignature生成のためのKey文字列
    """
    if oauth_token_secret == None:
        key = quote(consumer_secret, '') +"&"
    else:
        key = "%s&%s" % (quote(consumer_secret, ''), quote(oauth_token_secret, ''))

    #key = '&'.join([quote(key,'') for key in [consumer_secret, (oauth_token_secret or '')]])
    #print "Signature Key: "+ key
    return key

def normalize_data(http_method, request_url, header_params):
    """
    Signature生成のために、
    HTTPメソッド、対象URL、HTTPヘッダを&でつないで
    URLエンコードした文字列を生成する。

    Args:
    http_method: "POST"などのHTTPメソッドを表す文字列
    request_url: "https://hoge.com/oauth/initialize" などのリクエスト対象URL
    header_params: Authorizationヘッダに加えるもののうち、oauthで始まるパラメータでNoneでないものを抽出した辞書
    Returns:
        生成した文字列
    """
    query_str = '&'.join([
            '='.join(
                [key, quote(header_params.get(key, ''),'')]
            ) for key in sorted(header_params.keys())
    ])

    target_str = '&'.join(
        [quote(val,'')
         for val in [http_method.upper(), request_url.lower(), query_str]
         if val is not None])

    #print "Signature Data: "+ target_str
    return target_str

def make_signature(consumer_secret, http_method, request_url, header_params, oauth_token_secret=None ):
    """
    OAuth1.0のsignatureを生成する。
    Args:
    consumer_secret: consumer_secret文字列
    http_method: "POST"などのHTTPメソッドを表す文字列
    request_url: "https://hoge.com/oauth/initialize" などのリクエスト対象URL
    header_params: Authorizationヘッダに加えるもののうち、oauthで始まるパラメータでNoneでないものを抽出した辞書
    resource_owner_secret: (オプション) resource_owner_secret情報
    Returns:
    生成されたsignature文字列
    """
    import hashlib
    import hmac
    import base64

    normalized_key = normalize_key(consumer_secret, oauth_token_secret)
    normalized_data = normalize_data(http_method, request_url, header_params)

    signature = hmac.new(
                normalized_key.encode('utf-8'),
                normalized_data.encode('utf-8'),
                hashlib.sha1
            )
    return base64.b64encode(signature.digest()).decode('utf-8')

if __name__ == "__main__":
    print normalize_key("hogefuga")
    print normalize_data("POST", "https://hoge.com", {"oauth_callback": "oob"})

    print make_signature("hogefuga", "POST", "https://hoge.com", {"oauth_callback": "oob"} )
