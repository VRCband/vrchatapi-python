# World



## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**author_id** | **str** | A users unique ID, usually in the form of &#x60;usr_c1644b5b-3ca4-45b4-97c6-a2a0de70d469&#x60;. Legacy players can have old IDs in the form of &#x60;8JoV9XEdpo&#x60;. The ID can never be changed. | 
**author_name** | **str** |  | 
**capacity** | **int** |  | 
**recommended_capacity** | **int** |  | 
**created_at** | **datetime** |  | 
**default_content_settings** | [**InstanceContentSettings**](InstanceContentSettings.md) |  | [optional] 
**description** | **str** |  | 
**favorites** | **int** |  | [optional] [default to 0]
**featured** | **bool** |  | [default to False]
**heat** | **int** |  | [default to 0]
**id** | **str** | WorldID be \&quot;offline\&quot; on User profiles if you are not friends with that user. | 
**image_url** | **str** |  | 
**instances** | **list[list[object]]** | Will always be an empty list when unauthenticated. | [optional] 
**labs_publication_date** | **str** |  | 
**name** | **str** |  | 
**namespace** | **str** |  | [optional] 
**occupants** | **int** | Will always be &#x60;0&#x60; when unauthenticated. | [optional] [default to 0]
**organization** | **str** |  | [default to 'vrchat']
**popularity** | **int** |  | [default to 0]
**preview_youtube_id** | **str** |  | [optional] 
**private_occupants** | **int** | Will always be &#x60;0&#x60; when unauthenticated. | [optional] [default to 0]
**public_occupants** | **int** | Will always be &#x60;0&#x60; when unauthenticated. | [optional] [default to 0]
**publication_date** | **str** |  | 
**release_status** | [**ReleaseStatus**](ReleaseStatus.md) |  | 
**store_id** | **str** |  | [optional] 
**tags** | **list[str]** |   | 
**thumbnail_image_url** | **str** |  | 
**unity_packages** | [**list[UnityPackage]**](UnityPackage.md) | Empty if unauthenticated. | [optional] 
**updated_at** | **datetime** |  | 
**url_list** | **list[str]** |  | [optional] 
**version** | **int** |  | [default to 0]
**visits** | **int** |  | [default to 0]
**udon_products** | **list[str]** |  | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


