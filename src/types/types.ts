export interface ApiResponse<T=any>{
    success:boolean;
    message?:string;
    meta?:{
        requestId:string;
        timestamp:string;
        [key:string]:any;
    };
    data?:T;
}