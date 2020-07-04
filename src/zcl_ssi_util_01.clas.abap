CLASS zcl_ssi_util_01 DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC .

  PUBLIC SECTION.
    METHODS: get_csrf_token_and_cookie
      IMPORTING iv_url      TYPE string
                iv_USERNAME TYPE string
                iv_PASSWORD TYPE string
      EXPORTING et_cookies  TYPE tihttpcki
                ev_token    TYPE string
                ev_message  TYPE string,

      generate_csrf_token RETURNING VALUE(rv_result) TYPE string ,

      validate_csrf_token IMPORTING iv_token         TYPE string
                          RETURNING VALUE(rv_result) TYPE abap_bool .
  PROTECTED SECTION.
  PRIVATE SECTION.
ENDCLASS.

CLASS zcl_ssi_util_01 IMPLEMENTATION.
  METHOD get_csrf_token_and_cookie.
    DATA: lo_http_client TYPE REF TO if_http_client,
          lv_status      TYPE i,
          lt_fields      TYPE tihttpnvp,
          lv_sysubrc     TYPE sysubrc,
          lv_client      TYPE string.

    CALL METHOD cl_http_client=>create_by_url
      EXPORTING
        url                = iv_url
      IMPORTING
        client             = lo_http_client
      EXCEPTIONS
        argument_not_found = 1
        plugin_not_active  = 2
        internal_error     = 3
        OTHERS             = 4.

    ASSERT sy-subrc = 0.
    lo_http_client->propertytype_accept_cookie = if_http_client=>co_enabled.

    CALL METHOD lo_http_client->request->set_method( if_http_request=>co_request_method_get ).

    lv_client = sy-mandt.
    lo_http_client->request->set_header_field( name = if_rest_request=>gc_header_csrf_token value = 'Fetch' ).
    lo_http_client->request->set_header_field( name = 'Accept' value = if_rest_media_type=>gc_appl_json ).
    lo_http_client->request->set_header_field( name = 'Content-Type' value = if_rest_media_type=>gc_appl_json ).
    lo_http_client->request->set_header_field( name  = if_http_form_fields_sap=>sap_client value = lv_client ).
    lo_http_client->request->set_authorization( auth_type  = ihttp_auth_type_basic_auth
                                                username   = iv_username
                                                password   = iv_password ).

    lo_http_client->propertytype_logon_popup = if_http_client=>co_disabled.

    CALL METHOD lo_http_client->send
      EXCEPTIONS
        http_communication_failure = 1
        http_invalid_state         = 2
        http_processing_failed     = 3.

    ASSERT sy-subrc = 0.

    CALL METHOD lo_http_client->receive
      EXCEPTIONS
        http_communication_failure = 1
        http_invalid_state         = 2
        http_processing_failed     = 3.

    IF sy-subrc <> 0.
      CALL METHOD lo_http_client->get_last_error
        IMPORTING
          code    = lv_sysubrc
          message = ev_message.
      RETURN.
    ENDIF.

    lo_http_client->response->get_header_fields( CHANGING fields = lt_fields ).

    READ TABLE lt_fields ASSIGNING FIELD-SYMBOL(<field>) WITH KEY name = 'x-csrf-token'.
    ev_token = <field>-value.

    lo_http_client->response->get_cookies( CHANGING cookies = et_cookies ).
  ENDMETHOD.

  METHOD generate_csrf_token.
    DATA lv_tsl TYPE timestampl.
    DATA lv_gen TYPE string.
    DATA lv_time TYPE string.

    GET TIME STAMP FIELD lv_tsl.
    lv_time = lv_tsl.
    lv_gen = lv_time(11).
*Encode String to Base64
    CALL METHOD cl_http_utility=>if_http_utility~encode_base64
      EXPORTING
        unencoded = lv_gen
      RECEIVING
        encoded   = rv_result.
  ENDMETHOD.

  METHOD validate_csrf_token.
    DATA: lv_token TYPE string.
    DATA: lv_tsl   TYPE timestampl.
    DATA: lv_gen   TYPE string.
    DATA: lv_time  TYPE string.

    CALL METHOD cl_http_utility=>if_http_utility~decode_base64
      EXPORTING
        encoded = iv_token
      RECEIVING
        decoded = lv_token.
    GET TIME STAMP FIELD lv_tsl.
    lv_time = lv_tsl.
    lv_gen = lv_time(9).

    IF lv_gen EQ lv_token(9).
      rv_result = abap_true.
    ELSE.
      rv_result = abap_false.
    ENDIF.
  ENDMETHOD.

ENDCLASS.
