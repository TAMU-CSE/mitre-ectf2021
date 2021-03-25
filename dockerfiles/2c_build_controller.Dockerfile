# 2021 Collegiate eCTF
# SCEWL Bus Controller build Dockerfile
# Ben Janis
#
# (c) 2021 The MITRE Corporation

ARG DEPLOYMENT

###################################################################
# if you want to copy files from the sss container,               #
# first create an intermediate stage:                             #
#                                                                 #
# FROM ${DEPLOYMENT}:sss as sss                                   #
#                                                                 #
# Then see box below                                              #
###################################################################

# load base sss image
FROM ${DEPLOYMENT}/sss:latest AS sss

# load the base controller image
FROM ${DEPLOYMENT}/controller:base

# map in controller to /sed
# NOTE: only cpu/ and its subdirectories in the repo are accessible to this Dockerfile as .
ADD . /sed

###################################################################
# Copy files from the SSS container                               #
#                                                                 #
# COPY --from=sss /secrets/${SCEWL_ID}.secret /sed/sed.secret     #
#                                                                 #
###################################################################
# IT IS NOT RECOMMENDED TO KEEP DEPLOYMENT-WIDE SECRETS IN THE    #
# SED FILE STRUCTURE PAST BUILDING, SO CLEAN UP HERE AS NECESSARY #
###################################################################

# generate any other secrets and build controller
WORKDIR /sed

ARG SEMIHOSTED
# redundancy to build a little faster
RUN source $HOME/.cargo/env && cd scewl-rust && cargo build --release --features "$SEMIHOSTED" || exit 0

ARG SCEWL_ID

# copy shared registration secret
COPY --from=sss secrets/${SCEWL_ID}_secret /sed/${SCEWL_ID}_secret

RUN source $HOME/.cargo/env && cd scewl-rust && SCEWL_ID=${SCEWL_ID} cargo build --release --features "$SEMIHOSTED"
RUN mv /sed/scewl-rust/target/thumbv7m-none-eabi/release/controller /controller.elf
RUN arm-none-eabi-objcopy -O binary /controller.elf /controller

# NOTE: If you want to use the debugger with the scripts we provide, 
#       the ELF file must be at /controller.elf
#RUN mv /sed/gcc/controller.axf /controller.elf
